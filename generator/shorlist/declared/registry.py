"""The public tables a row is anchored on, read from the dated local copies in data/.

    data/iana/tls-parameters-8.csv   IANA TLS Supported Groups, read 2026-11-07
    data/iana/tls-parameters-4.csv   IANA TLS Cipher Suites, read 2026-11-07
    data/openssl-3.5.9-ciphers-V-stdname.txt
                                     `openssl ciphers -V -stdname ALL:@SECLEVEL=0` in the harness image
                                     (OpenSSL name <-> IANA name <-> code point), read 2026-11-07
    data/cryptography-defs.json      CycloneDX cryptography-defs (lastUpdated 2026-02-24): curve
                                     enum and aliases, algorithm families

The join key is always the IANA code point, written "0xXXXX" (scope rule: rows never join on OID).
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
SOURCES = {
    "iana-tls-groups": {"title": "IANA TLS Supported Groups registry",
                        "url": "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8",
                        "csv": "https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv",
                        "local": "data/iana/tls-parameters-8.csv", "date_read": "2026-11-07"},
    "iana-tls-ciphers": {"title": "IANA TLS Cipher Suites registry",
                         "url": "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4",
                         "csv": "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv",
                         "local": "data/iana/tls-parameters-4.csv", "date_read": "2026-11-07"},
    "openssl-ciphers-V": {"title": "OpenSSL 3.5.9 `openssl ciphers -V -stdname ALL:@SECLEVEL=0` in the harness image",
                          "url": "https://docs.openssl.org/3.5/man1/openssl-ciphers/",
                          "local": "data/openssl-3.5.9-ciphers-V-stdname.txt", "date_read": "2026-11-07"},
    "cdx-crypto-defs": {"title": "CycloneDX cryptography-defs.json (lastUpdated 2026-02-24)",
                        "url": "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/cryptography-defs.json",
                        "local": "data/cryptography-defs.json", "date_read": "2026-11-07"},
    "cdx-1.7-schema": {"title": "CycloneDX 1.7.2 JSON schema (byte-identical to tag 1.7.2)",
                       "url": "https://raw.githubusercontent.com/CycloneDX/specification/1.7.2/schema/bom-1.7.schema.json",
                       "local": "data/schema/bom-1.7.schema.json", "date_read": "2026-11-07"},
}
GROUPS_CSV, SUITES_CSV = DATA / "iana" / "tls-parameters-8.csv", DATA / "iana" / "tls-parameters-4.csv"
OSSL_TXT = DATA / "openssl-3.5.9-ciphers-V-stdname.txt"

# The groups the reference client (OpenSSL 3.5.9 s_client) offers, one at a time (scope rule S3).
CANDIDATE_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512", "MLKEM768", "MLKEM1024",
                    "x25519", "x448", "secp256r1", "secp384r1", "secp521r1",
                    "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192")
# Curve -> IANA group for the two Montgomery curves, which have no OID in cryptography-defs.
# RFC 8422 section 5.1.1 and RFC 7748: the TLS group x25519 / x448 is ECDH on Curve25519 / Curve448.
MONTGOMERY = {"curve25519": "x25519", "curve448": "x448"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def code_of(first_column: str) -> str:
    """IANA 'Value' column -> 0xXXXX: "0x13,0x01" (suites) or "4588" (groups)."""
    if "," in first_column:
        a, b = first_column.split(",")
        return "0x%02X%02X" % (int(a, 16), int(b, 16))
    return "0x%04X" % int(first_column)


@lru_cache
def lines() -> dict[str, str]:
    """Every verbatim line of the IANA copies -> the file it is in."""
    out = {}
    for f in (GROUPS_CSV, SUITES_CSV):
        out.update({ln: f.name for ln in f.read_text().splitlines()})
    return out


@lru_cache
def iana(category: str) -> dict[str, dict]:
    """code -> {name, description, line} for 'group' or 'cipher_suite'."""
    f = GROUPS_CSV if category == "group" else SUITES_CSV
    out = {}
    raw = f.read_text().splitlines()
    for ln in raw[1:]:
        row = next(csv.reader([ln]))
        try:
            code = code_of(row[0])
        except ValueError:
            continue  # ranges ("0-255") and "Unassigned" blocks
        out[code] = {"name": row[1], "line": ln, "description": row[5] if len(row) > 5 else ""}
    return out


@lru_cache
def openssl_suites() -> dict[str, dict]:
    """code -> {openssl, iana, version, line} from `openssl ciphers -V -stdname`."""
    out = {}
    for ln in OSSL_TXT.read_text().splitlines():
        m = re.match(r"\s*(0x[0-9A-F]{2},0x[0-9A-F]{2}) - (\S+)\s+- (\S+)\s+(\S+)", ln)
        if m:
            out[code_of(m.group(1))] = {"iana": m.group(2), "openssl": m.group(3), "version": m.group(4), "line": ln.strip()}
    return out


def candidate_suites() -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """(TLS 1.3, TLS 1.2) suites the reference client offers, one at a time: every suite OpenSSL 3.5.9
    lists under ALL:@SECLEVEL=0, TLS 1.3 by its IANA name, TLS 1.2 / SSLv3 by code point."""
    s13, s12 = [], []
    for code, s in sorted(openssl_suites().items()):
        (s13 if s["version"] == "TLSv1.3" else s12).append((code, s["iana"]))
    return s13, s12


@lru_cache
def curves() -> dict[str, str]:
    """Every cryptography-defs curve spelling ('secg/secp256r1', 'x962/prime256v1', 'other/Curve25519',
    and the bare names) -> the IANA group name, via the shared OID; Montgomery curves via MONTGOMERY."""
    defs = json.loads((DATA / "cryptography-defs.json").read_text())
    by_oid: dict[str, list[str]] = {}
    names = {}
    for cat in defs["ellipticCurves"]:
        for c in cat["curves"]:
            full = f"{cat['name']}/{c['name']}"
            names[full] = c
            if c.get("oid"):
                by_oid.setdefault(c["oid"], []).append(full)
    groups = {v["name"].lower(): v["name"] for v in iana("group").values()}
    out = {}
    for full, c in names.items():
        target = None
        if c["name"].lower() in MONTGOMERY:
            target = MONTGOMERY[c["name"].lower()]
        elif c.get("oid"):
            for other in by_oid[c["oid"]]:  # secg/secp256r1 shares the OID with nist/P-256 and x962/prime256v1
                if other.split("/", 1)[1].lower() in groups:
                    target = groups[other.split("/", 1)[1].lower()]
        if target:
            out[full.lower()] = target
            out[c["name"].lower()] = target
    return out


def norm_hex(s: str) -> str | None:
    """'0x11EC', '0x11ec', '0x13,0x01', "['0x13','0x01']" pieces joined -> 0xXXXX, else None."""
    s = s.strip().replace(" ", "")
    m = re.fullmatch(r"0x([0-9A-Fa-f]{2}),?0x([0-9A-Fa-f]{2})", s)
    if m:
        return "0x" + (m.group(1) + m.group(2)).upper()
    m = re.fullmatch(r"0x([0-9A-Fa-f]{1,4})", s)
    if m:
        return "0x%04X" % int(m.group(1), 16)
    return None


def group_code(spelling: str) -> str | None:
    """A tlsGroups string -> IANA code: the IANA name (case-insensitive; unique in the registry) or a
    code point written in hex."""
    h = norm_hex(spelling)
    if h and h in iana("group"):
        return h
    for code, g in iana("group").items():
        if g["name"].lower() == spelling.strip().lower():
            return code
    return None


def suite_code(identifiers: list[str] | None, name: str | None) -> str | None:
    """cipherSuite -> IANA code: `identifiers` joined (['0x13','0x01'] or ['0x13,0x01']), else `name`
    as an IANA or OpenSSL name."""
    if identifiers:
        h = norm_hex("".join(i.strip() for i in identifiers).replace("0x", ",0x").lstrip(","))
        if h is None and len(identifiers) == 1:
            h = norm_hex(identifiers[0])
        if h and h in iana("cipher_suite"):
            return h
    if name:
        for code, s in iana("cipher_suite").items():
            if s["name"] == name:
                return code
        for code, s in openssl_suites().items():
            if s["openssl"] == name:
                return code
    return None


def group_family(code: str) -> str | None:
    """Family of a TLS group, for parameter_mismatch and family-level declarations (S8). From
    cryptography-defs: ECDH covers ECDH[E][-{ellipticCurve}] and x25519|x448; FFDH covers
    FFDH[E][-{namedGroup}]; ML-KEM covers ML-KEM-(512|768|1024). A hybrid has no family."""
    name = iana("group")[code]["name"].lower()
    if name in ("x25519", "x448") or name in curves():
        return "ECDH"
    if name.startswith("ffdhe"):
        return "FFDH"
    if re.fullmatch(r"mlkem(512|768|1024)", name):
        return "ML-KEM"
    return None


def hybrid_parts(code: str) -> frozenset[str] | None:
    """A hybrid group's halves, read from the IANA description column: "Combining X25519 ECDH with
    ML-KEM-768" -> {x25519, ML-KEM-768}. None for a group that is not a hybrid."""
    d = iana("group")[code]["description"]
    m = re.fullmatch(r"(?:PQ/T hybrid )?[Cc]ombining (\S+)(?: ECDH)? with (\S+)(?: ECDH)?", d)
    if not m:
        return None
    parts = set()
    for p in m.groups():
        q = p.lower()
        parts.add(q.upper() if q.startswith("ml-kem") else curves().get(q, MONTGOMERY.get(q, q)))
    return frozenset(parts)


def data_sha256() -> dict[str, str]:
    return {str(p.relative_to(DATA)): sha256(p) for p in sorted(DATA.rglob("*")) if p.is_file()}
