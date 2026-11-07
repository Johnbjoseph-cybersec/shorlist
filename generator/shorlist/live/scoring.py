"""Score one scanner's observations against a row's wire items, and build the result tables.

Per row and scanner, in this order:
    out_of_scope      the row's protocol is not one the scanner speaks (left out of its tables)
    not_runnable      wire.yaml says so (cloud, appliance, not_attempted), or the server refused the
                      row's configuration at run time (config_rejected, with the server's own error)
    not_scored        wire.yaml says so (not_on_wire, comment_decoy, no_scanner), or the reference
                      client contradicts the expectation on this server: a `seen` item is not on the wire
                      (not_offered) or a `not_seen` item is (expectation_contradicted)
    scanner_error     the scanner exited without a parseable result, or timed out
    false_alarm       the scanner reported a `not_seen` item
    hit               every `seen` item was reported (a row with seen items)
    ok                nothing `not_seen` was reported (a row with only not_seen items: a decoy)
    miss              a `seen` item was not reported
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from .scanners import group

SCORED = ("hit", "miss", "false_alarm", "ok")


def matches(item: dict, obs: set) -> bool:
    kind = item["kind"]
    names = {item["name"].lower(), *(a.lower() for a in item.get("aliases", []))}
    if kind == "group":
        names |= {group(n).lower() for n in names}
    for k, v in obs:
        if k != kind:
            continue
        v = str(v)
        if item.get("code") and v.upper() == item["code"].upper():
            return True
        if v.lower() in names or (kind == "group" and group(v).lower() in names):
            return True
    return False


def score(wire_row: dict, run: dict, obs: set | None) -> dict:
    """`run`: {"status": started|config_rejected, "error", "reference": [...], "scanner_error"}."""
    if "not_runnable" in wire_row:
        out = {"outcome": "not_runnable", "reason": wire_row["not_runnable"]}
        if wire_row["not_runnable"] == "config_rejected" and run.get("status") == "started":
            out["wire_mismatch"] = "wire.yaml says config_rejected, but the server started in this run"
        return out
    if "not_scored" in wire_row:
        return {"outcome": "not_scored", "reason": wire_row["not_scored"]}
    if run.get("status") == "config_rejected":
        return {"outcome": "not_runnable", "reason": "config_rejected", "error": run.get("error", "")}
    ref = run.get("reference") or []
    if any(r["expect"] == "seen" and r.get("on_wire") is False for r in ref):
        return {"outcome": "not_scored", "reason": "not_offered"}
    if any(r["expect"] == "not_seen" and r.get("on_wire") is True for r in ref):
        return {"outcome": "not_scored", "reason": "expectation_contradicted"}
    if run.get("scanner_error") or obs is None:
        return {"outcome": "scanner_error", "error": run.get("scanner_error", "no output")}
    items = wire_row["items"]
    seen = [i for i in items if i["expect"] == "seen"]
    alarms = [i["name"] for i in items if i["expect"] == "not_seen" and matches(i, obs)]
    if alarms:
        return {"outcome": "false_alarm", "reported": alarms}
    if seen:
        missing = [i["name"] for i in seen if not matches(i, obs)]
        return {"outcome": "miss", "missing": missing} if missing else {"outcome": "hit"}
    return {"outcome": "ok"}


def table(scored: list[dict], key: str) -> dict:
    t: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for s in scored:
        cell = t[s[key]]
        cell[s["outcome"] + ("/" + s["reason"] if s.get("reason") else "")] += 1
        if s["outcome"] in SCORED:
            cell["positive" if not s["negative"] else "decoys"] += 1
    return {k: dict(v) for k, v in sorted(t.items())}


def fingerprint(wire_sha: str, cat_sha: str, gen_version: str, scanner_version: str, images: dict, scored: list[dict]) -> str:
    body = {"wire_sha256": wire_sha, "catalogue_sha256": cat_sha, "generator_version": gen_version,
            "scanner_version": scanner_version, "images": images,
            "rows": [[s["id"], s["outcome"], s.get("reason")] for s in scored]}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def summary(scored: list[dict]) -> dict:
    pos = [s for s in scored if not s["negative"] and s["outcome"] in SCORED]
    neg = [s for s in scored if s["negative"] and s["outcome"] in SCORED]
    c = lambda xs, o: sum(s["outcome"] == o for s in xs)  # noqa: E731
    other = defaultdict(int)
    for s in scored:
        if s["outcome"] not in SCORED:
            other[s["outcome"] + ("/" + s["reason"] if s.get("reason") else "")] += 1
    return {"positive": {"n": len(pos), "hit": c(pos, "hit"), "miss": c(pos, "miss"), "false_alarm": c(pos, "false_alarm")},
            "decoys": {"n": len(neg), "ok": c(neg, "ok"), "false_alarm": c(neg, "false_alarm")},
            "not_scored": dict(sorted(other.items()))}


def controls(adapter, scored: list[dict]) -> dict:
    by_id = {s["id"]: s for s in scored}
    out = {}
    for proto, (catch, decoy) in adapter.controls.items():
        c, d = by_id.get(catch), by_id.get(decoy)
        out[proto] = {
            "catch": catch, "catch_outcome": c["outcome"] if c else "not run",
            "decoy": decoy, "decoy_outcome": d["outcome"] if d else "not run",
            "passed": bool(c and d and c["outcome"] == "hit" and d["outcome"] == "ok"),
        }
    return out


def markdown(result: dict) -> str:
    s = result["summary"]
    p, d = s["positive"], s["decoys"]
    L = [f"**{result['statement']}**", "",
         f"wire.yaml sha256 `{result['wire']['sha256'][:16]}…` · catalogue {result['catalogue']['version']} sha256 "
         f"`{result['catalogue']['sha256'][:16]}…` · generator {result['generator']['version']} · "
         f"fingerprint `{result['fingerprint'][:16]}…`", "",
         "| positive rows | hit | miss | false alarm | decoys | ok | false alarm |", "|---|---|---|---|---|---|---|",
         f"| {p['n']} | {p['hit']} | {p['miss']} | {p['false_alarm']} | {d['n']} | {d['ok']} | {d['false_alarm']} |", ""]
    if s["not_scored"]:
        L += ["Not scored: " + ", ".join(f"{k} {v}" for k, v in s["not_scored"].items()), ""]
    L += ["| positive control | catch row | outcome | decoy row | outcome | passed |", "|---|---|---|---|---|---|"]
    for proto, c in result["positive_controls"].items():
        L.append(f"| {proto} | {c['catch']} | {c['catch_outcome']} | {c['decoy']} | {c['decoy_outcome']} | {'yes' if c['passed'] else 'NO'} |")
    L.append("")
    for key, title in (("by_server", "server"), ("by_family", "family")):
        L += [f"| {title} | hit / positive | false alarm / decoys | not scored |", "|---|---|---|---|"]
        for k, c in result[key].items():
            ns = ", ".join(f"{o} {n}" for o, n in c.items() if o.split("/")[0] not in SCORED and o not in ("positive", "decoys"))
            L.append(f"| {k} | {c.get('hit', 0)} / {c.get('positive', 0)} | "
                     f"{sum(v for o, v in c.items() if o == 'false_alarm')} / {c.get('decoys', 0)} | {ns or '—'} |")
        L.append("")
    L += ["| id | server | decoy | literal | outcome | detail | reference client |", "|---|---|---|---|---|---|---|"]
    for r in result["rows"]:
        det = r.get("reason") or ", ".join(r.get("missing", []) or r.get("reported", [])) or ""
        if r.get("error"):
            det += ": " + r["error"][:120].replace("|", "\\|").replace("\n", " ")
        ref = "; ".join(f"{x['name']} {'on wire' if x.get('on_wire') else ('not on wire' if x.get('on_wire') is False else '?')}"
                        for x in r.get("reference", [])[:3])
        lit = r["literal"].replace("|", "\\|")
        L.append(f"| {r['id']} | {r.get('server', '—')} | {'yes' if r['negative'] else ''} | `{lit}` | {r['outcome']} | {det or '—'} | {ref or '—'} |")
    return "\n".join(L) + "\n"
