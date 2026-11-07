"""Run one tool over every row (no network, no server: the observations are already captured)."""
from __future__ import annotations

import platform
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from . import observed, registry, rows as rowsmod, scoring
from .adapters import TOOLS, Reference

RESULT_FORMAT = "declared-0.1"


def run(tool_name: str, keep: Path | None = None, only: set[str] | None = None, log=print) -> dict:
    tool = TOOLS[tool_name]()
    rows = rowsmod.load()
    errs = rowsmod.problems(rows)
    if errs:
        raise ValueError("declared rows invalid:\n  " + "\n  ".join(errs))
    lst = rowsmod.listeners()
    version = tool.version()
    scored, raw = [], {}
    for r in rows:
        if only and r["id"] not in only:
            continue
        if "not_scored" in r:
            scored.append(scoring.score(r, None) | {"server": "-", "listener": "-"})
            continue
        obs = rowsmod.observation(r["listener"])
        ocbom = observed.build(obs)
        cat = r["compare"]["category"]
        if isinstance(tool, Reference):
            out = tool.compare(r["declaration"], obs, cat)
            raw[r["id"]] = {"reference": out["reference"]}
        else:
            rr = tool.run(r["declaration"], ocbom, keep / r["id"] if keep else None)
            raw[r["id"]] = {"exit": rr["exit"]}
            try:
                out = tool.parse(rr["stdout"], r["declaration"], ocbom)
                raw[r["id"]]["unmapped"] = out["unmapped"]
            except (ValueError, KeyError, TypeError) as e:
                out = {"error": f"exit {rr['exit']}: {type(e).__name__}: {e}; stderr: {rr['stderr'][-300:]}"}
        s = scoring.score(r, out)
        s.update(server=lst[r["listener"]]["server"], listener=r["listener"])
        if "findings" in out:
            s["tool_findings"] = [f for f in out["findings"] if f["category"] == cat]
        scored.append(s)
        log(f"{r['id']}  {s['server']:<8} {cat:<12} {r['verdict']:<18} -> {s.get('tool_verdict', '-'):<24} {s['outcome']}")
    summ = scoring.summary(scored)
    p, c = summ["non_consistent"], summ["consistent"]
    rsha = rowsmod.rows_sha256()
    label = " (reference comparator: positive control, not a scanner)" if isinstance(tool, Reference) else ""
    res = {
        "result_format": RESULT_FORMAT,
        "axis": "declared",
        "statement": (f"Of {p['n']} non-consistent pairs on the ShorList declaration axis, {version}{label} reproduces "
                      f"{p['hit']} verdicts ({p['partial']} partial); of {c['n']} consistent pairs ({summ['decoys']['n']} of "
                      f"them decoys), it raises {c['false_alarm']} false alarms. {summ['not_scored']} SSH rows are not "
                      "scored (no_spec_structure, CycloneDX #1162)."),
        "rows": {"n": len(scored), "sha256": rsha, **rowsmod.stats(rows)},
        "data_sha256": registry.data_sha256(),
        "generator": {"name": "shorlist", "version": __version__},
        "tool": {"name": tool.name, "version": version, "image": tool.image, "image_id": tool.image_id(),
                 "command": tool.command()},
        "observed_cbom": "observed.build(): one protocol component per TLS version, IANA names, identifiers in IANA CSV form",
        "summary": summ,
        "by_verdict": scoring.table(scored, "verdict"),
        "by_server": scoring.table(scored, "server"),
        "by_decoy": scoring.table([s for s in scored if s.get("verdict") == "consistent"], "decoy_class"),
        "by_category": scoring.table(scored, "category"),
        "rows_scored": scored,
        "fingerprint": scoring.fingerprint(rsha, __version__, version, scored),
        "fingerprint_rule": "sha256(canonical JSON {rows_sha256, generator_version, tool_version, rows:[[id,outcome,reason]...]})",
        "run": {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "python": platform.python_version(),
                "platform": platform.platform()},
        "raw": raw,
    }
    if isinstance(tool, Reference):
        ok = p["hit"] == p["n"] and c["ok"] == c["n"]
        res["controls"] = (f"positive control {'PASSED' if ok else 'FAILED'}: the reference comparator must score "
                           f"{p['n']}/{p['n']} hits and {c['n']}/{c['n']} ok")
        res["control_passed"] = ok
    return res
