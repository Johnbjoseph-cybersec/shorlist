"""Adapter for CSNP CryptoScan (https://github.com/csnp/cryptoscan), run in a container.

Output read: the CycloneDX 1.6 CBOM of `cryptoscan scan <dir> --format cbom`, whose fields are
documented in docs/cbom-fields.md at v1.5.0
(https://github.com/csnp/cryptoscan/blob/v1.5.0/docs/cbom-fields.md). The JSON format has no
field reference, so it is not used.

Mapping (shared CycloneDX rules in _cyclonedx.py):
- one Record per components[].evidence.occurrences[] (`location` relative to the scan root,
  `line`); family from `name` via schema/families.yaml, after the names below;
- CryptoScan's own names, mapped as its pattern table defines them (PATTERNS.md at v1.5.0,
  https://github.com/csnp/cryptoscan/blob/v1.5.0/PATTERNS.md):
  - "ECC" -> EC. L139: `| ECC-001 | Elliptic Curve | VULNERABLE | High | `ECDSA`, `ECDH`,
    `P-256`, `secp256r1`, `Ed25519`, `Curve25519` |`. The name does not say which EC
    algorithm, so it is the parent family; for an expected ECDSA the scorer gives parent_only.
  - "Hybrid-KEM" -> ML-KEM. L117: `| HYBRID-KEM-001 | X25519+ML-KEM Hybrid Key Exchange |
    HYBRID | Info | `X25519MLKEM768`, `X25519Kyber768`, hybrid key exchange combinations |`.
    The pattern's regex (pkg/patterns/matcher.go L1243) also matches a bare "hybrid kem" /
    "hybrid key exchange"; the documentation names only ML-KEM hybrids, and that is followed.
  - "Composite-Signature" -> ML-DSA. L118-119: HYBRID-SIG-001 "ECDSA+ML-DSA Composite
    Signatures", HYBRID-SIG-002 "RSA+ML-DSA Composite Signatures".
  - "HMAC-MD5" -> MD5 and "HMAC-SHA1" -> SHA-1 (weak axis; the catalogue files `hmac-md5`,
    `hmac-sha1` under MD5 and SHA-1). pkg/patterns/matcher.go at v1.5.0, L1317-1324:
    `ID: "MAC-HMAC-MD5-001"`, `Algorithm: "HMAC-MD5"`, `Description: "HMAC-MD5 detected. MD5 is
    cryptographically broken. Not NIST-approved."`; L1302-1310: `ID: "MAC-HMAC-SHA1-001"`,
    `Algorithm: "HMAC-SHA1"`, `Description: "HMAC-SHA1 detected. SHA-1 is deprecated for new
    applications."`. Without them the shared prefix rule gives HMAC (defect_only), out of scope.
  "Hybrid-TLS" is not in the pattern table and "RSA, ECDSA" names two families; both stay
  unmapped. "Weak Certificate Signature (SHA-1)" (CERT-SIGALG-WEAK-001) stays unmapped too: its
  rule matches `sha1WithRSA` and `md5WithRSA` alike (PATTERNS.md L261; matcher.go L801 "SHA-1 or
  MD5"), so the name does not say which. "Weak Cipher Suite" (CIPHER-001) names no algorithm;
- cwe: None. CryptoScan writes no CWE: none in the CBOM, the SARIF or the JSON output of a scan
  of all 187 defect rows of v0.2 (grep -i cwe on each, 0 lines), and none in the docs
  (PATTERNS.md, docs/commands.md, docs/cbom-fields.md at v1.5.0);
- role: from algorithmProperties.primitive (signature / kem / key-agree), else None;
- size: None. The CBOM's classicalSecurityLevel is a security strength, not a key size, and
  relatedCryptoMaterialProperties.size is documented as never written;
- is_use: True for everything; the CBOM has no not-a-use marker.

Invocation: default scan settings plus --no-config (a config file in the planted tree must not
change the result). The scan exits 1 when a finding is CRITICAL (docs/commands.md, "Exit
codes"); the CBOM is read whatever the exit code.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import _cyclonedx
from ._container import OUT, SCAN, ContainerAdapter
from .base import Record

ALIASES = {"ECC": "EC", "Hybrid-KEM": "ML-KEM", "Composite-Signature": "ML-DSA",  # PATTERNS.md L117-119, L139
           "HMAC-MD5": "MD5", "HMAC-SHA1": "SHA-1"}  # matcher.go L1317-1324, L1302-1310


class CryptoScanAdapter(ContainerAdapter):
    name = "cryptoscan"
    image = "shorlist-cryptoscan:1.5.0"

    def version(self) -> str:
        return self.run_plain(["version"]).strip().splitlines()[0].strip()

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = self.outdir(tree, workdir)
        p = self.run_scan(tree, out, ["scan", SCAN, "--no-config", "--format", "cbom", "--output", f"{OUT}/cbom.json"])
        f = out / "cbom.json"
        if not f.exists():
            raise RuntimeError(f"cryptoscan wrote no CBOM (exit {p.returncode}): {p.stderr.strip()[:500]}")
        return self.parse(json.loads(f.read_text()))

    @staticmethod
    def parse(bom: dict) -> list[Record]:
        return _cyclonedx.records(bom, aliases=ALIASES)
