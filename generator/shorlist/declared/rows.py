"""Load and validate the declaration-axis rows, listeners and captured observations."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

import yaml

from . import observed, reference, registry, servers

HERE = Path(__file__).resolve().parent
ROWS, OBS, LISTENERS = HERE / "rows", HERE / "observations", HERE / "listeners.yaml"
VERDICTS = ("consistent", "undeclared", "overclaimed", "parameter_mismatch")
DECOYS = ("identifier_spelling", "hybrid_spelling", "parent_child", "inactive_scope")
CATEGORIES = ("group", "cipher_suite")


@lru_cache
def validator():
    from jsonschema import Draft7Validator
    sd = registry.DATA / "schema"
    subs = {f: json.loads((sd / f).read_text()) for f in ("cryptography-defs.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")}
    schema = json.loads((sd / "bom-1.7.schema.json").read_text())
    try:
        from referencing import Registry, Resource
    except ImportError:  # jsonschema < 4.18: the older resolver, same documents
        from jsonschema import RefResolver
        store = {u + f: s for f, s in subs.items() for u in ("", "http://cyclonedx.org/schema/")}
        return Draft7Validator(schema, resolver=RefResolver.from_schema(schema, store=store))
    reg = Registry()
    for f, s in subs.items():
        res = Resource.from_contents(s)
        reg = reg.with_resource(f, res).with_resource("http://cyclonedx.org/schema/" + f, res)
    return Draft7Validator(schema, registry=reg)


def schema_errors(bom: dict) -> list[str]:
    return [f"{e.message[:160]} at {list(e.absolute_path)}" for e in validator().iter_errors(bom)]


def listeners() -> dict[str, dict]:
    return yaml.safe_load(LISTENERS.read_text())["listeners"]


def load() -> list[dict]:
    return [yaml.safe_load(p.read_text()) for p in sorted(ROWS.glob("*.yaml"))]


def observation(lid: str) -> dict | None:
    p = OBS / f"{lid}.json"
    return json.loads(p.read_text()) if p.exists() else None


def scored(rows: list[dict]) -> list[dict]:
    return [r for r in rows if "not_scored" not in r]


OBS_FINGERPRINTED = ("listener", "observation_status", "method", "server", "server_image", "config_sha256", "candidates",
                     "accepted")


def rows_sha256() -> str:
    """sha256 over every row file and listeners.yaml (bytes), and over the semantic part of every
    observation (OBS_FINGERPRINTED: not captured_at, the local harness image id or the raw evidence), so
    a re-capture that finds the same accepted sets keeps every result fingerprint."""
    h = hashlib.sha256()
    for p in sorted(ROWS.glob("*.yaml")) + [LISTENERS]:
        h.update(p.name.encode() + b"\0" + p.read_bytes() + b"\0")
    for p in sorted(OBS.glob("*.json")):
        o = json.loads(p.read_text())
        body = json.dumps({k: o.get(k) for k in OBS_FINGERPRINTED}, sort_keys=True, separators=(",", ":"))
        h.update(p.name.encode() + b"\0" + body.encode() + b"\0")
    return h.hexdigest()


def _quotes_ok(rid: str, res: dict) -> list[str]:
    errs = []
    qs = res.get("quote")
    for q in (qs if isinstance(qs, list) else [qs] if qs else []):
        if q in registry.lines():
            from csv import reader
            if registry.code_of(next(reader([q]))[0]) != res["code"]:
                errs.append(f"{rid}: code {res['code']} != quote {q}")
        elif not any(q == s["line"] for s in registry.openssl_suites().values()):
            errs.append(f"{rid}: quote not verbatim in any source: {q}")
    if "code" in res and not qs:
        errs.append(f"{rid}: resolves_to {res.get('at')} has a code and no quote")
    return errs


def problems(rows: list[dict] | None = None) -> list[str]:
    rows = load() if rows is None else rows
    errs: list[str] = []
    lst = listeners()
    if yaml.safe_load((registry.DATA / "SOURCES.yaml").read_text()) != registry.SOURCES:
        errs.append("data/SOURCES.yaml differs from registry.SOURCES")
    seen = set()
    for r in rows:
        rid = r.get("id", "?")
        if rid in seen:
            errs.append(f"{rid}: duplicate id")
        seen.add(rid)
        if "not_scored" in r:
            if r["not_scored"] != "no_spec_structure" or "1162" not in r.get("reason", ""):
                errs.append(f"{rid}: not_scored rows must say no_spec_structure and cite CycloneDX #1162")
            continue
        cat = r["compare"]["category"]
        if r["verdict"] not in VERDICTS or cat not in CATEGORIES or r["compare"]["protocol"] != "tls":
            errs.append(f"{rid}: verdict/category/protocol {r['verdict']}/{cat}/{r['compare']['protocol']}")
            continue
        if r.get("decoy_class") not in (None, *DECOYS) or (r.get("decoy_class") and r["verdict"] != "consistent"):
            errs.append(f"{rid}: decoy_class {r.get('decoy_class')} on a {r['verdict']} row")
        if (r["focus"] is None) != (r["verdict"] == "consistent"):
            errs.append(f"{rid}: focus must be null exactly for consistent rows")
        errs += [f"{rid}: declaration schema: {e}" for e in schema_errors(r["declaration"])]
        f = r["focus"] or {}
        for res in r.get("resolves_to", []) + [x for x in (f, f.get("declared"), f.get("observed")) if x and "code" in x]:
            errs += _quotes_ok(rid, res)
            for k in (res.get("source") if isinstance(res.get("source"), list) else [res.get("source")]):
                if k not in registry.SOURCES:
                    errs.append(f"{rid}: source {k!r} not in data/SOURCES.yaml")
        if r["listener"] not in lst:
            errs.append(f"{rid}: no listener {r['listener']}")
            continue
        obs = observation(r["listener"])
        if obs is None:
            errs.append(f"{rid}: no captured observation for {r['listener']} (run: declared --capture)")
            continue
        if obs.get("observation_status") != "captured" or obs.get("method") != "accepted":
            errs.append(f"{rid}: observation is not a captured accepted-set probe")
        if obs.get("config_sha256") != servers.config_sha256(lst[r["listener"]]):
            errs.append(f"{rid}: listener {r['listener']} changed after its capture (re-run declared --capture)")
        for c, items in obs["accepted"].items():
            for it in items:
                if registry.iana(c).get(it["code"], {}).get("name") != it["name"]:
                    errs.append(f"{rid}: accepted {it} is not that IANA {c}")
        errs += [f"{rid}: observed CBOM schema: {e}" for e in schema_errors(observed.build(obs))]
        # the reference comparator, from the pair alone, must give the row's verdict and focus
        ref = reference.compare(r["declaration"], obs, cat)
        if ref["verdict"] != r["verdict"]:
            errs.append(f"{rid}: reference says {ref['verdict']} ({ref.get('reason', '')}), row says {r['verdict']}")
        elif r["verdict"] == "parameter_mismatch":
            f = r["focus"]
            if ref["focus"] != {"declared": f["declared"]["code"], "observed": f["observed"]["code"], "family": f["family"]}:
                errs.append(f"{rid}: reference focus {ref['focus']} != row focus")
        elif r["verdict"] != "consistent" and ref["focus"] != r["focus"]["code"]:
            errs.append(f"{rid}: reference focus {ref['focus']} != row focus {r['focus']['code']}")
        # the human ground truth (resolves_to) must name what the reference resolved, nothing more or less
        in_scope = [x for x in r.get("resolves_to", []) if "out of scope" not in x.get("at", "")]
        want = {x["code"] for x in in_scope if "code" in x}
        if want != set(ref["declared"]):
            errs.append(f"{rid}: resolves_to codes {sorted(want)} != reference resolution {ref['declared']}")
        if {x["family"] for x in in_scope if "family" in x} != set(ref["declared_families"]):
            errs.append(f"{rid}: resolves_to families != reference families {ref['declared_families']}")
    return errs


def stats(rows: list[dict] | None = None) -> dict:
    rows = load() if rows is None else rows
    lst = listeners()
    out: dict = {"rows": len(rows), "not_scored": sum("not_scored" in r for r in rows), "by_verdict": {}, "by_server": {},
                 "by_category": {}, "by_decoy": {}, "listeners": len(lst)}
    for r in scored(rows):
        for k, v in (("by_verdict", r["verdict"]), ("by_server", lst[r["listener"]]["server"]),
                     ("by_category", r["compare"]["category"]), ("by_decoy", r.get("decoy_class") or "-")):
            out[k][v] = out[k].get(v, 0) + 1
    return out
