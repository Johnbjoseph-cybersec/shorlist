"""Shared reading of CycloneDX 1.6/1.7 CBOM components, for the scanners that write one.

Reference: CycloneDX 1.6 JSON reference, https://cyclonedx.org/docs/1.6/json/ (components[].
cryptoProperties, components[].evidence.occurrences[]); CycloneDX 1.7 adds
algorithmProperties.algorithmFamily; algorithm naming: cryptography-defs.json,
https://raw.githubusercontent.com/CycloneDX/specification/master/schema/cryptography-defs.json
(names are "<family>[-<parameter>]…", e.g. "ML-KEM-768", "RSASSA-PKCS1-2048-SHA256").

Family: the names of schema/families.yaml are the vocabulary. A name (algorithmFamily first,
then the component name) maps to a family when, case-insensitively, it or one of its leading
"-"-separated prefixes is a family key or appears in a family's `cyclonedx` list there
(RSASSA-PKCS1 -> RSA, FFDH -> DH). Nothing else is mapped: a scanner's own spellings outside
that vocabulary ("ECC", "SHA256withECDSA") stay as they are and the scorer ignores them.

Role: from algorithmProperties.primitive: signature -> signature; kem, key-agree ->
key_establishment; any other value (pke, other, …) -> None, because CycloneDX's `pke` is used
for RSA and EC keys alike and does not say which role the key has.

Size: relatedCryptoMaterialProperties.size (bits) when present; parameterSetIdentifier only
for a scanner that documents it as the key size (`size_from_parameter_set=True`).
classicalSecurityLevel is a security strength, not a key size, and is not used.
"""
from __future__ import annotations

from ..catalogue import load_families
from ._container import rel_path
from .base import Record

ROLE = {"signature": "signature", "kem": "key_establishment", "key-agree": "key_establishment"}


def _vocabulary() -> dict[str, str]:
    fams = load_families()
    v: dict[str, str] = {}
    for fam, d in fams.items():
        for cdx in d.get("cyclonedx") or []:
            v.setdefault(cdx.upper(), fam)
    for fam in fams:  # a family's own name wins (ECDH -> ECDH, not X25519)
        v[fam.upper()] = fam
    return v


VOCAB = _vocabulary()


def family(name: str | None) -> str | None:
    if not name:
        return None
    parts = str(name).strip().split("-")
    for n in range(len(parts), 0, -1):
        hit = VOCAB.get("-".join(parts[:n]).upper())
        if hit:
            return hit
    return None


def component_family(c: dict) -> str:
    ap = (c.get("cryptoProperties") or {}).get("algorithmProperties") or {}
    return family(ap.get("algorithmFamily")) or family(c.get("name")) or str(c.get("name", ""))


def component_role(c: dict) -> str | None:
    ap = (c.get("cryptoProperties") or {}).get("algorithmProperties") or {}
    return ROLE.get(str(ap.get("primitive", "")).lower())


def component_size(c: dict, size_from_parameter_set: bool = False) -> int | None:
    cp = c.get("cryptoProperties") or {}
    s = (cp.get("relatedCryptoMaterialProperties") or {}).get("size")
    if s is None and size_from_parameter_set:
        s = (cp.get("algorithmProperties") or {}).get("parameterSetIdentifier")
    try:
        return int(s) if s is not None else None
    except (TypeError, ValueError):
        return None


def occurrences(c: dict) -> list[tuple[str, int | None]]:
    """CycloneDX evidence.occurrences[] -> [(path relative to the tree, line)], outside the tree dropped."""
    out = []
    for o in ((c.get("evidence") or {}).get("occurrences") or []):
        p = rel_path(o.get("location", ""))
        if p:
            line = o.get("line")
            out.append((p, int(line) if line is not None else None))
    return out


def crypto_components(bom: dict) -> list[dict]:
    return [c for c in bom.get("components") or [] if c.get("type") == "cryptographic-asset"]


def records(bom: dict, *, size_from_parameter_set: bool = False, locations=occurrences) -> list[Record]:
    """One Record per (cryptographic-asset component, occurrence in the planted tree).
    A component with no occurrence in the tree gives no Record. CBOMs have no not-a-use marker,
    so is_use is True."""
    recs = []
    for c in crypto_components(bom):
        fam, role, size = component_family(c), component_role(c), component_size(c, size_from_parameter_set)
        for path, line in locations(c):
            recs.append(Record(path=path, line=line, family=fam, role=role, size=size, is_use=True))
    return recs
