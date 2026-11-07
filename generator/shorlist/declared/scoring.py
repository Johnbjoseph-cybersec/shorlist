"""Score a tool's findings against each row, and build the result (PROUCHVANE.md section 4.3).

Only findings in the row's `compare.category` count; a tool is not penalised for reporting cipher
suites on a group row. Per row:
    hit          non-consistent row; exactly one finding, of the row's verdict, naming the focus
                 element (any spelling that denotes the focus code point; for parameter_mismatch both
                 the declared and the accepted item)
    partial      parameter_mismatch row reported as exactly undeclared(accepted focus) +
                 overclaimed(declared focus), not linked. Its own column, never folded into hit
    miss         non-consistent row otherwise: nothing reported, wrong verdict, wrong element, or
                 more findings than the one difference the row has (reason says which)
    false_alarm  consistent row (every decoy is one) with any finding in the category
    ok           consistent row, nothing reported in the category
    not_scored   SSH rows (no_spec_structure)
    tool_error   the tool exited without parseable output
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from . import registry

OUTCOMES = ("hit", "partial", "miss", "false_alarm", "ok", "tool_error")


def element_codes(el: dict, category: str, row: dict) -> set[str]:
    """Every code point a reported element can denote: via the row's resolves_to (by bom-ref), or the
    element's own spelling read against the registries."""
    out = set()
    ref = el.get("ref")
    for r in row.get("resolves_to", []):
        if ref and r.get("ref") == ref and "code" in r:
            out.add(r["code"])
    if category == "cipher_suite":
        c = registry.suite_code(el.get("identifiers"), el.get("name") or el.get("value"))
        h = registry.norm_hex(str(el.get("value") or ""))
        out |= {x for x in (c, h) if x and x in registry.iana("cipher_suite")}
    else:
        for k in ("value", "name"):
            if el.get(k):
                c = registry.group_code(str(el[k]))
                if c:
                    out.add(c)
    return out


def score(row: dict, out: dict | None) -> dict:
    s = {"id": row["id"], "verdict": row.get("verdict"), "category": row["compare"]["category"],
         "decoy_class": row.get("decoy_class")}
    if "not_scored" in row:
        return s | {"outcome": "not_scored", "reason": row["not_scored"]}
    if out is None or "error" in out:
        return s | {"outcome": "tool_error", "reason": (out or {}).get("error", "no output")}
    cat, v, focus = row["compare"]["category"], row["verdict"], row["focus"]
    f = [x for x in out["findings"] if x["category"] == cat]
    s["findings"] = len(f)
    s["tool_verdict"] = ("consistent" if not f else f[0]["verdict"] if len({x["verdict"] for x in f}) == 1 and len(f) == 1
                         else "+".join(sorted({x["verdict"] for x in f})) + f" x{len(f)}")
    if v == "consistent":
        return s | ({"outcome": "ok", "reason": ""} if not f else
                    {"outcome": "false_alarm", "reason": "; ".join(x["tool_says"] for x in f)[:400]})
    if not f:
        return s | {"outcome": "miss", "reason": "nothing reported in the category"}
    if v == "parameter_mismatch":
        dc, oc = focus["declared"]["code"], focus["observed"]["code"]
        if len(f) == 1 and f[0]["verdict"] == v:
            el = f[0]["element"]
            ok = dc in element_codes({"value": el.get("declared"), "ref": el.get("ref")} if "declared" in el else el, cat, row) \
                and oc in element_codes({"value": el.get("observed")} if "observed" in el else el, cat, row)
            return s | ({"outcome": "hit", "reason": ""} if ok else {"outcome": "miss", "reason": "parameter_mismatch on another element"})
        by = sorted(x["verdict"] for x in f)
        if by == ["overclaimed", "undeclared"]:
            o = next(x for x in f if x["verdict"] == "overclaimed")
            u = next(x for x in f if x["verdict"] == "undeclared")
            if dc in element_codes(o["element"], cat, row) and oc in element_codes(u["element"], cat, row):
                return s | {"outcome": "partial", "reason": "undeclared + overclaimed, not linked"}
        return s | {"outcome": "miss", "reason": f"reported {s['tool_verdict']}"}
    want = focus["code"]
    right = [x for x in f if x["verdict"] == v and want in element_codes(x["element"], cat, row)]
    if len(f) == 1 and right:
        return s | {"outcome": "hit", "reason": ""}
    if right:
        return s | {"outcome": "miss", "reason": f"the focus is reported, with {len(f) - 1} further finding(s)"}
    if any(x["verdict"] == v for x in f):
        return s | {"outcome": "miss", "reason": "right verdict, wrong element"}
    return s | {"outcome": "miss", "reason": f"reported {s['tool_verdict']}"}


def table(scored: list[dict], key: str) -> dict:
    t: dict[str, dict] = defaultdict(lambda: {"n": 0, **{o: 0 for o in OUTCOMES}})
    for s in scored:
        if s["outcome"] == "not_scored":
            continue
        cell = t[s.get(key) or "-"]
        cell["n"] += 1
        cell[s["outcome"]] += 1
    return dict(sorted(t.items()))


def summary(scored: list[dict]) -> dict:
    pos = [s for s in scored if s["outcome"] != "not_scored" and s["verdict"] != "consistent"]
    neg = [s for s in scored if s["outcome"] != "not_scored" and s["verdict"] == "consistent"]
    c = lambda xs, o: sum(s["outcome"] == o for s in xs)  # noqa: E731
    return {"non_consistent": {"n": len(pos), "hit": c(pos, "hit"), "partial": c(pos, "partial"), "miss": c(pos, "miss"),
                               "tool_error": c(pos, "tool_error")},
            "consistent": {"n": len(neg), "ok": c(neg, "ok"), "false_alarm": c(neg, "false_alarm"),
                           "tool_error": c(neg, "tool_error")},
            "decoys": {"n": sum(bool(s["decoy_class"]) for s in neg),
                       "false_alarm": sum(bool(s["decoy_class"]) and s["outcome"] == "false_alarm" for s in neg)},
            "not_scored": sum(s["outcome"] == "not_scored" for s in scored)}


def fingerprint(rows_sha: str, gen_version: str, tool_version: str, scored: list[dict]) -> str:
    body = {"rows_sha256": rows_sha, "generator_version": gen_version, "tool_version": tool_version,
            "rows": [[s["id"], s["outcome"], s.get("reason", "")] for s in scored]}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def markdown(res: dict) -> str:
    out = [f"**{res['tool']['version']}** on the ShorList declaration axis ({res['rows']['n']} rows, "
           f"rows sha256 `{res['rows']['sha256'][:12]}`, fingerprint `{res['fingerprint'][:16]}`)", "",
           res["statement"], ""]
    cols = ("n", "hit", "partial", "miss", "false_alarm", "ok", "tool_error")
    for title, key in (("By verdict class", "by_verdict"), ("By server", "by_server"), ("By decoy class (consistent rows)", "by_decoy"),
                       ("By category", "by_category")):
        out += [f"*{title}*", "", "| " + key.split("_", 1)[1] + " | " + " | ".join(cols) + " |",
                "|---|" + "---:|" * len(cols)]
        for k, cell in res[key].items():
            out.append(f"| {k} | " + " | ".join(str(cell[c]) for c in cols) + " |")
        out.append("")
    if res.get("controls"):
        out += [f"*Controls*: {res['controls']}", ""]
    return "\n".join(out)
