"""Adapter for Semgrep Community Edition (https://github.com/semgrep/semgrep) with the public
crypto rules of https://github.com/semgrep/semgrep-rules.

Ruleset: every rule file under a directory of semgrep-rules whose path contains "crypt"
(case-insensitive), test fixtures excluded, at the commit baked into the image (written to
/rules/VERSION). The rule files are not part of this repository (Semgrep Rules License v1.0).
The selection was fixed before the first scan. A registry ruleset (`--config p/...`) cannot be
used, because the scan runs with no network.

Output read: `semgrep scan --json`, the CLI JSON output (https://semgrep.dev/docs/cli-reference,
schema: semgrep-interfaces semgrep_output_v1): results[].check_id, .path, .start.line.

Mapping:
- one Record per result, at (path, start.line);
- family: Semgrep results carry no algorithm field. The family is taken from the tokens of
  `check_id` (split on . - _): a token equal, case-insensitively, to a family name or one of its
  CycloneDX names in schema/families.yaml (e.g. "...insufficient-rsa-key-size" -> RSA). A
  result with no such token keeps its check_id as family, which the scorer ignores.
  Three tokens the rules use for a weak family under another spelling are mapped as the rule
  that carries the token defines it (semgrep-rules @16b9e6d4):
  - "sha1" -> SHA-1: java/lang/security/audit/crypto/use-of-sha1.yaml L2-4 `id: use-of-sha1`,
    "Detected SHA1 hash algorithm which is considered insecure" (the same message in
    go/.../use_of_weak_crypto.yaml L36-38 and python/cryptography/security/
    insecure-hash-algorithms.yaml L2, L13; L41 of the Java rule matches `(SHA1|SHA-1)`);
  - "arc4" -> RC4: python/cryptography/security/insecure-cipher-algorithms-arc4.yaml L2-4
    `id: insecure-cipher-algorithm-arc4`, "ARC4 (Alleged RC4) is a stream cipher";
  - "desede" -> 3DES: java/lang/security/audit/crypto/desede-is-deprecated.yaml L2-4
    `id: desede-is-deprecated`, "Triple DES (3DES or DESede) is considered deprecated".
  python/pycryptodome/security/insecure-cipher-algorithm-des ("Detected DES cipher or Triple
  DES algorithm") names both; its "des" token gives DES, so on a DES3 row it scores
  wrong_family;
- role and size: None, not in the output;
- is_use: True; Semgrep reports matches, not uses;
- cwe: from the rule metadata the JSON output carries per result, `extra.metadata.cwe`. The
  rules' metadata schema (semgrep-rules metadata-schema.yaml.schm L54-61 at 16b9e6d4) defines
  `cwe` as a string or an array of strings with `pattern: ^CWE-\\d+.*`, written as
  'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'; the leading "CWE-NNN" is kept.
  A result with several CWEs gives one Record per CWE; a result with none, one Record with
  cwe None.

Invocation: --metrics=off --disable-version-check.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ._container import OUT, SCAN, ContainerAdapter, rel_path
from ._cyclonedx import VOCAB
from .base import Record


TOKEN_ALIASES = {"SHA1": "SHA-1", "ARC4": "RC4", "DESEDE": "3DES"}  # rule files cited above


def family_from_check_id(check_id: str) -> str:
    for tok in re.split(r"[._-]", check_id):
        fam = VOCAB.get(tok.upper()) or TOKEN_ALIASES.get(tok.upper())
        if fam:
            return fam
    return check_id


CWE = re.compile(r"^\s*(CWE)-(\d+)", re.IGNORECASE)


def cwes(metadata: dict) -> list[str]:
    """metadata.cwe (a string or a list of 'CWE-NNN: title') -> ['CWE-NNN', ...], in order, no repeats."""
    v = metadata.get("cwe")
    out: list[str] = []
    for item in [v] if isinstance(v, str) else (v or []):
        m = CWE.match(str(item))
        if m and f"CWE-{int(m.group(2))}" not in out:
            out.append(f"CWE-{int(m.group(2))}")
    return out


class SemgrepAdapter(ContainerAdapter):
    name = "semgrep"
    image = "shorlist-semgrep:1.183.0"

    def version(self) -> str:
        v = self.run_plain(["--version", "--disable-version-check"]).strip().splitlines()[-1].strip()
        rules = self.run_plain(["/rules/VERSION"], entrypoint="cat").strip()
        return f"semgrep {v} + {rules}"

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = self.outdir(tree, workdir)
        p = self.run_scan(tree, out, ["scan", "--config", "/rules", "--metrics=off", "--disable-version-check",
                                      "--json", "--output", f"{OUT}/semgrep.json", SCAN])
        f = out / "semgrep.json"
        if not f.exists():
            raise RuntimeError(f"semgrep wrote no result (exit {p.returncode}): {p.stderr.strip()[-500:]}")
        return self.parse(json.loads(f.read_text()))

    @staticmethod
    def parse(result: dict) -> list[Record]:
        recs = []
        for r in result.get("results") or []:
            path = rel_path(r.get("path", ""))
            if not path:
                continue
            line, fam = (r.get("start") or {}).get("line"), family_from_check_id(r.get("check_id", ""))
            for cwe in cwes((r.get("extra") or {}).get("metadata") or {}) or [None]:
                recs.append(Record(path=path, line=line, family=fam, cwe=cwe))
        return recs
