"""Plant every row into its own tree, run the scanner, score, and build the result."""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .adapters.base import Adapter
from .catalogue import ROOT, catalogue_sha256, catalogue_version, load, load_families

RESULT_FORMAT = "0.2"  # 0.2: catalogue.by_axis, axes, per-row axis, fix


def plant(row: dict, base: Path, *, fixed: bool = False) -> Path:
    """Write the row's template (or, with fixed=True, its right_template) into a fresh tree."""
    tree = base / row["id"] / ("fix" if fixed else "tree")
    tree.mkdir(parents=True)
    (tree / row["context_filename"]).write_text(row["right_template" if fixed else "context_template"])
    return tree


def _table(scored: list[dict], rows_by_id: dict, key: str) -> dict:
    t: dict[str, dict] = defaultdict(lambda: {"positive": 0, "hit": 0, "decoys": 0, "false_alarm": 0})
    for s in scored:
        cell = t[rows_by_id[s["id"]][key]]
        if s["negative"]:
            cell["decoys"] += 1
            cell["false_alarm"] += s["outcome"] == "false_alarm"
        else:
            cell["positive"] += 1
            cell["hit"] += s["outcome"] == "hit"
    return dict(sorted(t.items()))


def _axes(scored: list[dict]) -> dict:
    """Summaries of the weak and defect axes; an axis with no rows is left out."""
    out: dict[str, dict] = {}
    counts = lambda xs, o: sum(s["outcome"] == o for s in xs)  # noqa: E731
    weak = [s for s in scored if s["axis"] == "weak"]
    if weak:
        pos, neg = [s for s in weak if not s["negative"]], [s for s in weak if s["negative"]]
        out["weak"] = {
            "positive": {o: counts(pos, o) for o in ("hit", "parent_only", "wrong_family", "miss")} | {"n": len(pos)},
            "decoys": {o: counts(neg, o) for o in ("ok", "false_alarm")} | {"n": len(neg)},
            "size_ok": {"true": sum(s["size_ok"] is True for s in pos), "false": sum(s["size_ok"] is False for s in pos)},
        }
    defect = [s for s in scored if s["axis"] == "defect"]
    if defect:
        pos, neg = [s for s in defect if not s["negative"]], [s for s in defect if s["negative"]]
        fixes = [s["fix"] for s in defect if "fix" in s]
        out["defect"] = {
            "positive": {o: counts(pos, o) for o in ("hit", "wrong_class", "miss")} | {"n": len(pos)},
            "decoys": {o: counts(neg, o) for o in ("ok", "false_alarm")} | {"n": len(neg)},
            "fixed_files": {o: counts(fixes, o) for o in ("ok", "false_alarm")} | {"n": len(fixes)},
        }
    return out


def fingerprint(cat_sha: str, gen_version: str, scanner_version: str, scored: list[dict]) -> str:
    """sha256 of the canonical JSON of catalogue sha, generator version, scanner version and
    the ordered per-row (id, outcome, role_ok, size_ok)."""
    body = {
        "catalogue_sha256": cat_sha,
        "generator_version": gen_version,
        "scanner_version": scanner_version,
        "rows": [[s["id"], s["outcome"], s.get("role_ok"), s.get("size_ok")] + ([s["fix"]["outcome"]] if "fix" in s else [])
                 for s in scored],
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run(adapter: Adapter, root: Path = ROOT, keep: Path | None = None,
        shard: tuple[int, int] | None = None) -> dict:
    """Scan every row; with shard=(i, n), only the rows whose catalogue index is i mod n.

    A shard result is not a measurement on its own: `merge` joins all n shards into the
    result an unsharded run gives (same rows, same fingerprint)."""
    from .score import score_fix, score_row

    rows = load(root)
    families = load_families(root)
    scanner_version = adapter.version()
    todo = rows if shard is None else [r for k, r in enumerate(rows) if k % shard[1] == shard[0]]
    base = Path(tempfile.mkdtemp(prefix="shorlist-"))
    scored, raw = [], {}
    try:
        for row in todo:
            tree = plant(row, base)
            work = base / row["id"] / "work"
            work.mkdir()
            recs = adapter.scan(tree, work)
            raw[row["id"]] = [r.to_dict() for r in recs]
            s = score_row(row, recs, families)
            if "right_template" in row:
                fix_tree = plant(row, base, fixed=True)
                fix_work = base / row["id"] / "fix-work"
                fix_work.mkdir()
                fix_recs = adapter.scan(fix_tree, fix_work)
                raw[row["id"] + "/fix"] = [r.to_dict() for r in fix_recs]
                s["fix"] = score_fix(row, fix_recs)
            scored.append(s)
    finally:
        if keep:
            if keep.exists():
                shutil.rmtree(keep)
            shutil.copytree(base, keep)
        shutil.rmtree(base, ignore_errors=True)

    scanner = {"adapter": adapter.name, "command": adapter.command, "version": scanner_version}
    run_meta = {  # not part of the fingerprint
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": platform.python_version(), "platform": platform.platform(),
    }
    if shard is not None:
        return {"result_format": RESULT_FORMAT, "shard": {"index": shard[0], "of": shard[1]},
                "catalogue": {"version": catalogue_version(root), "sha256": catalogue_sha256(root)},
                "generator": {"name": "shorlist", "version": __version__}, "scanner": scanner,
                "rows": scored, "run": run_meta, "raw_records": raw}
    return assemble(root, scanner, scored, raw, run_meta)


def merge(shards: list[dict], root: Path = ROOT) -> dict:
    """Join the n shard results of one scanner into the result of an unsharded run."""
    if not shards:
        raise ValueError("no shards")
    n = shards[0]["shard"]["of"]
    if sorted(s["shard"]["index"] for s in shards) != list(range(n)) or any(s["shard"]["of"] != n for s in shards):
        raise ValueError(f"need shards 0..{n - 1} of {n}, each once")
    for key in ("catalogue", "generator", "scanner"):
        if any(s[key] != shards[0][key] for s in shards):
            raise ValueError(f"shards differ in {key}")
    if shards[0]["generator"]["version"] != __version__:
        raise ValueError("shards were made by another generator version")
    if shards[0]["catalogue"]["sha256"] != catalogue_sha256(root):
        raise ValueError("shards were measured on another catalogue than root")
    by_id = {r["id"]: r for s in shards for r in s["rows"]}
    rows = load(root)
    if set(by_id) != {r["id"] for r in rows}:
        raise ValueError("shard rows do not cover the catalogue")
    raw = {k: v for s in shards for k, v in s["raw_records"].items()}
    run_meta = {"shards": [s["run"] for s in sorted(shards, key=lambda s: s["shard"]["index"])]}
    return assemble(root, shards[0]["scanner"], [by_id[r["id"]] for r in rows], raw, run_meta)


def assemble(root: Path, scanner: dict, scored: list[dict], raw: dict, run_meta: dict) -> dict:
    rows = load(root)
    rows_by_id = {r["id"]: r for r in rows}
    scanner_version = scanner["version"]

    # The headline summary and the by_* tables are the quantum axis only, so adding weak or
    # defect rows never moves them. The other axes are reported apart under "axes".
    quantum = [s for s in scored if s["axis"] == "quantum"]
    pos = [s for s in quantum if not s["negative"]]
    neg = [s for s in quantum if s["negative"]]
    counts = lambda xs, o: sum(s["outcome"] == o for s in xs)  # noqa: E731
    cat_sha = catalogue_sha256(root)
    version = catalogue_version(root)
    m, la = counts(pos, "hit"), counts(neg, "false_alarm")
    return {
        "result_format": RESULT_FORMAT,
        "catalogue": {"name": "ShorList", "version": version, "sha256": cat_sha,
                      "rows": len(rows), "positive": len(pos), "decoys": len(neg),
                      "by_axis": {a: sum(s["axis"] == a for s in scored) for a in ("quantum", "weak", "defect")}},
        "generator": {"name": "shorlist", "version": __version__},
        "scanner": scanner,
        "summary": {
            "statement": (f"Of {len(pos)} positive forms in ShorList {version}, {scanner_version} recognises "
                          f"{m}; of {len(neg)} decoys it reports {la} as a use. This measures recognition of "
                          f"a form in a minimal context; it is not recall and not finding in a real tree."),
            "positive": {o: counts(pos, o) for o in ("hit", "parent_only", "wrong_family", "miss")} | {"n": len(pos)},
            "decoys": {o: counts(neg, o) for o in ("ok", "false_alarm")} | {"n": len(neg)},
            "role_ok": {"true": sum(s["role_ok"] is True for s in pos), "false": sum(s["role_ok"] is False for s in pos)},
            "size_ok": {"true": sum(s["size_ok"] is True for s in pos), "false": sum(s["size_ok"] is False for s in pos)},
        },
        "axes": _axes(scored),
        "by_form_kind": _table(quantum, rows_by_id, "form_kind"),
        "by_family": _table(quantum, rows_by_id, "family"),
        "by_language_or_product": _table(quantum, rows_by_id, "language_or_product"),
        "rows": scored,
        "fingerprint": fingerprint(cat_sha, __version__, scanner_version, scored),
        "fingerprint_rule": "sha256(canonical JSON {catalogue_sha256, generator_version, scanner_version, rows:[[id,outcome,role_ok,size_ok]...]})",
        "run": run_meta,  # not part of the fingerprint
        "raw_records": raw,
    }


def markdown(result: dict) -> str:
    """Human-readable tables for a result."""
    L = [f"**{result['summary']['statement']}**", "",
         f"catalogue {result['catalogue']['version']} sha256 `{result['catalogue']['sha256'][:16]}…` · "
         f"generator {result['generator']['version']} · fingerprint `{result['fingerprint'][:16]}…`", ""]
    p, d = result["summary"]["positive"], result["summary"]["decoys"]
    L += ["| positive forms | hit | parent only | wrong family | miss | decoys | ok | false alarm |",
          "|---|---|---|---|---|---|---|---|",
          f"| {p['n']} | {p['hit']} | {p['parent_only']} | {p['wrong_family']} | {p['miss']} | {d['n']} | {d['ok']} | {d['false_alarm']} |", ""]
    for key, title in (("by_form_kind", "form_kind"), ("by_family", "family"), ("by_language_or_product", "language / product")):
        L += [f"| {title} | positive: hit / n | decoys: false alarm / n |", "|---|---|---|"]
        for k, c in result[key].items():
            L.append(f"| {k} | {c['hit']} / {c['positive']} | {c['false_alarm']} / {c['decoys']} |")
        L.append("")
    for axis, a in result.get("axes", {}).items():
        p, d = a["positive"], a["decoys"]
        L += [f"**{axis} axis** (scored apart; not in the figures above)", "",
              "| positive | " + " | ".join(k for k in p if k != "n") + " | decoys | ok | false alarm |" + (" fixed files | false alarm |" if "fixed_files" in a else ""),
              "|" + "---|" * (len(p) + 3 + (2 if "fixed_files" in a else 0)),
              f"| {p['n']} | " + " | ".join(str(v) for k, v in p.items() if k != "n") + f" | {d['n']} | {d['ok']} | {d['false_alarm']} |"
              + (f" {a['fixed_files']['n']} | {a['fixed_files']['false_alarm']} |" if "fixed_files" in a else ""), ""]
    L += ["| id | decoy | outcome | reported as use | reported as not-use | role ok | size ok |", "|---|---|---|---|---|---|---|"]
    fmt = lambda v: "—" if v is None else ("yes" if v else "no")  # noqa: E731
    for s in result["rows"]:
        if s["axis"] == "defect":
            fix = f"; fixed file: {s['fix']['outcome']}" if "fix" in s else ""
            L.append(f"| {s['id']} | {'yes' if s['negative'] else ''} | {s['outcome']}{fix} | {', '.join(s['reported_cwe']) or '—'} | — | — | — |")
            continue
        L.append(f"| {s['id']} | {'yes' if s['negative'] else ''} | {s['outcome']} | {', '.join(s['reported_as_use']) or '—'} | "
                 f"{', '.join(s['reported_not_use']) or '—'} | {fmt(s.get('role_ok'))} | {fmt(s.get('size_ok'))} |")
    return "\n".join(L) + "\n"
