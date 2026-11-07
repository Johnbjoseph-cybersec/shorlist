"""REFERENCE COMPARATOR - NOT A SCANNER AND NOT A TOOL UNDER TEST.

The positive control of this axis: a plain implementation of scope rules S1-S10 (PROUCHVANE.md
section 5.2) over the declared CBOM and the captured observation, using only the public tables in
registry.py. It must reproduce every row's verdict; if it does, each row is decidable from the pair
and the published registries alone. It does not read a row's `resolves_to`, `verdict` or `focus`.

    S5  declared groups = union of cipherSuites[].tlsGroups over the in-scope protocol components,
        plus the group of every key-agree / kem / combiner algorithm referenced from cipherSuites[].algorithms
    S6  declared suites = cipherSuites[] of the in-scope protocol components, keyed by the code point
        `identifiers` denotes (or, without it, `name`, as an IANA or OpenSSL name)
    S7  in scope = protocol components whose `scope` is absent or `required`
    S8  a family without a parameter set or curve covers every accepted child of that family
    S9  a hybrid is its IANA group name in tlsGroups, or a `combiner` whose dependencies name both
        halves; halves reached only through a combiner are not declared on their own
    S3  a declared item outside the reference client's candidates cannot be overclaimed (undecidable)
"""
from __future__ import annotations

import re

from . import registry

LABEL = "reference comparator (positive control; not a scanner)"


def _components(decl: dict) -> dict[str, dict]:
    out = {}

    def walk(cs):
        for c in cs or []:
            if c.get("bom-ref"):
                out[c["bom-ref"]] = c
            walk(c.get("components"))
    walk(decl.get("components"))
    return out


def in_scope_protocols(decl: dict) -> list[dict]:
    return [c for c in _components(decl).values()
            if c.get("type") == "cryptographic-asset"
            and (c.get("cryptoProperties") or {}).get("assetType") == "protocol"
            and ((c["cryptoProperties"].get("protocolProperties") or {}).get("type") == "tls")
            and c.get("scope", "required") == "required"]


def _half(c: dict) -> str | None:
    """One half of a hybrid: an IANA ECDH group name (x25519, secp256r1) or ML-KEM-<n>."""
    ap = (c.get("cryptoProperties") or {}).get("algorithmProperties") or {}
    if ap.get("primitive") == "kem":
        m = re.fullmatch(r"(?:ML-KEM-?)?(512|768|1024)", str(ap.get("parameterSetIdentifier", "")))
        if (ap.get("algorithmFamily") == "ML-KEM" or c.get("name", "").upper().startswith("ML-KEM")) and m:
            return f"ML-KEM-{m.group(1)}"
        m = re.fullmatch(r"ML-KEM-(512|768|1024)", c.get("name", ""), re.I)
        return f"ML-KEM-{m.group(1)}" if m else None
    if ap.get("primitive") == "key-agree":
        curve = ap.get("ellipticCurve") or ap.get("curve")
        if curve:
            return registry.curves().get(str(curve).lower())
        if c.get("name", "").lower() in ("x25519", "x448"):  # cryptography-defs ECDH variant pattern x25519|x448
            return c["name"].lower()
    return None


def _algorithm_group(c: dict, deps: dict[str, list[str]], comps: dict[str, dict]) -> tuple[str, str] | None:
    """A referenced algorithm -> ('code', 0xXXXX) or ('family', ECDH|FFDH|ML-KEM), or None."""
    ap = (c.get("cryptoProperties") or {}).get("algorithmProperties") or {}
    prim = ap.get("primitive")
    if prim == "combiner":
        halves = frozenset(h for h in (_half(comps[r]) for r in deps.get(c.get("bom-ref"), []) if r in comps) if h)
        for code in registry.iana("group"):
            if registry.hybrid_parts(code) == halves and len(halves) == 2:
                return ("code", code)
        return None
    if prim in ("key-agree", "kem"):
        h = _half(c)
        if h:
            if h.startswith("ML-KEM-"):
                return ("code", registry.group_code("MLKEM" + h.split("-")[-1]))
            code = registry.group_code(h)
            return ("code", code) if code else None
        fam = ap.get("algorithmFamily") or {"EC": "ECDH", "ECDH": "ECDH", "ECDHE": "ECDH", "ML-KEM": "ML-KEM",
                                             "FFDH": "FFDH", "DH": "FFDH"}.get(c.get("name", "").upper())
        if fam in ("ECDH", "FFDH", "ML-KEM"):
            return ("family", fam)
    return None


def declared(decl: dict, category: str) -> dict:
    """{'codes': {code: [spelling]}, 'families': {family: [spelling]}, 'unresolved': [spelling]}"""
    comps = _components(decl)
    deps = {d["ref"]: d.get("dependsOn", []) for d in decl.get("dependencies", [])}
    codes: dict[str, list[str]] = {}
    fams: dict[str, list[str]] = {}
    unresolved: list[str] = []
    for p in in_scope_protocols(decl):
        ref = p.get("bom-ref", p.get("name"))
        for i, cs in enumerate(p["cryptoProperties"]["protocolProperties"].get("cipherSuites", [])):
            at = f"{ref} cipherSuites[{i}]"
            if category == "cipher_suite":
                code = registry.suite_code(cs.get("identifiers"), cs.get("name"))
                (codes.setdefault(code, []) if code else unresolved).append(at)
                continue
            for j, g in enumerate(cs.get("tlsGroups", [])):
                code = registry.group_code(g)
                (codes.setdefault(code, []) if code else unresolved).append(f"{at} tlsGroups[{j}]={g}")
            for r in cs.get("algorithms", []):
                c = comps.get(r)
                if c is None:
                    unresolved.append(f"{at} algorithms -> {r} (no such bom-ref)")
                    continue
                kind = _algorithm_group(c, deps, comps)
                if kind and kind[0] == "code":
                    codes.setdefault(kind[1], []).append(r)
                elif kind:
                    fams.setdefault(kind[1], []).append(r)
                # any other referenced algorithm (cipher, hash, signature) is not a group
    return {"codes": codes, "families": fams, "unresolved": unresolved}


def compare(decl: dict, obs: dict, category: str) -> dict:
    """The verdict for one category: consistent | undeclared | overclaimed | parameter_mismatch,
    or undecidable (more than one difference, an unresolvable spelling, or S3)."""
    d = declared(decl, category)
    accepted = {a["code"] for a in obs["accepted"][category]}
    candidates = set(obs["candidates"][category])
    fam = registry.group_family if category == "group" else (lambda code: None)
    covered = lambda a: a in d["codes"] or fam(a) in d["families"]  # noqa: E731
    under = sorted(a for a in accepted if not covered(a))
    over = sorted(c for c in d["codes"] if c not in accepted)
    over_fam = sorted(f for f in d["families"] if not any(fam(a) == f for a in accepted))
    items = {c: "consistent" for c in d["codes"] if c in accepted}
    items |= {a: "consistent" for a in accepted if covered(a)}
    items |= {a: "undeclared" for a in under} | {c: "overclaimed" for c in over}
    out = {"category": category, "declared": sorted(d["codes"]), "declared_families": sorted(d["families"]),
           "accepted": sorted(accepted), "undeclared": under, "overclaimed": over, "items": dict(sorted(items.items()))}
    if d["unresolved"]:
        return out | {"verdict": "undecidable", "reason": f"unresolved spelling: {d['unresolved']}"}
    if [c for c in over if c not in candidates]:
        return out | {"verdict": "undecidable", "reason": "S3: declared item outside the reference client's candidates"}
    if over_fam:
        return out | {"verdict": "undecidable", "reason": f"declared family with no accepted child: {over_fam}"}
    if not under and not over:
        return out | {"verdict": "consistent", "focus": None}
    if len(under) == 1 and len(over) == 1 and fam(under[0]) and fam(under[0]) == fam(over[0]):
        out["items"] |= {under[0]: "parameter_mismatch", over[0]: "parameter_mismatch"}
        return out | {"verdict": "parameter_mismatch", "focus": {"declared": over[0], "observed": under[0], "family": fam(under[0])}}
    if len(under) == 1 and not over:
        return out | {"verdict": "undeclared", "focus": under[0]}
    if len(over) == 1 and not under:
        return out | {"verdict": "overclaimed", "focus": over[0]}
    return out | {"verdict": "undecidable", "reason": f"{len(under)} undeclared and {len(over)} overclaimed items"}
