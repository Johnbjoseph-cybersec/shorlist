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
from .adapters.base import Adapter, ScannerTimeout
from .catalogue import ROOT, catalogue_sha256, catalogue_version, load, load_families, row_axis

POSITIVE = ("hit", "parent_only", "wrong_family", "file_only", "miss")
ERROR = "scanner_error"

RESULT_FORMAT = "0.3"  # 0.2: catalogue.by_axis, axes, per-row axis, fix; 0.3: file_only, scanner_error


def plant(row: dict, base: Path, *, fixed: bool = False) -> Path:
    """Write the row's template (or, with fixed=True, its right_template) into a fresh tree."""
    tree = base / row["id"] / ("fix" if fixed else "tree")
    tree.mkdir(parents=True)
    (tree / row["context_filename"]).write_text(row["right_template" if fixed else "context_template"])
    return tree


def _scored(xs: list[dict]) -> list[dict]:
    """The rows that were scored: scanner_error rows are left out of every denominator."""
    return [s for s in xs if s["outcome"] != ERROR]


def _errors(xs: list[dict]) -> dict:
    ids = [s["id"] for s in xs if s["outcome"] == ERROR]
    return {"n": len(ids), "ids": ids}


def _table(scored: list[dict], rows_by_id: dict, key: str) -> dict:
    t: dict[str, dict] = defaultdict(lambda: {"positive": 0, "hit": 0, "file_only": 0, "decoys": 0, "false_alarm": 0})
    for s in _scored(scored):
        cell = t[rows_by_id[s["id"]][key]]
        if s["negative"]:
            cell["decoys"] += 1
            cell["false_alarm"] += s["outcome"] == "false_alarm"
        else:
            cell["positive"] += 1
            cell["hit"] += s["outcome"] == "hit"
            cell["file_only"] += s["outcome"] == "file_only"
    return dict(sorted(t.items()))


def _axes(scored: list[dict]) -> dict:
    """Summaries of the weak and defect axes; an axis with no rows is left out."""
    out: dict[str, dict] = {}
    counts = lambda xs, o: sum(s["outcome"] == o for s in xs)  # noqa: E731
    weak = [s for s in scored if s["axis"] == "weak"]
    if weak:
        ok = _scored(weak)
        pos, neg = [s for s in ok if not s["negative"]], [s for s in ok if s["negative"]]
        out["weak"] = {
            "positive": {o: counts(pos, o) for o in POSITIVE} | {"n": len(pos)},
            "decoys": {o: counts(neg, o) for o in ("ok", "false_alarm")} | {"n": len(neg)},
            "size_ok": {"true": sum(s["size_ok"] is True for s in pos), "false": sum(s["size_ok"] is False for s in pos)},
            "scanner_error": _errors(weak),
        }
    defect = [s for s in scored if s["axis"] == "defect"]
    if defect:
        ok = _scored(defect)
        pos, neg = [s for s in ok if not s["negative"]], [s for s in ok if s["negative"]]
        fixes = _scored([s["fix"] for s in ok if "fix" in s])
        out["defect"] = {
            "positive": {o: counts(pos, o) for o in ("hit", "wrong_class", "miss")} | {"n": len(pos)},
            "decoys": {o: counts(neg, o) for o in ("ok", "false_alarm")} | {"n": len(neg)},
            "fixed_files": {o: counts(fixes, o) for o in ("ok", "false_alarm")} | {"n": len(fixes)},
            "scanner_error": _errors(defect),
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


def run(adapter: Adapter, root: Path = ROOT, keep: Path | None = None) -> dict:
    from .score import score_fix, score_row

    rows = load(root)
    families = load_families(root)
    rows_by_id = {r["id"]: r for r in rows}
    scanner_version = adapter.version()
    base = Path(tempfile.mkdtemp(prefix="shorlist-"))
    scored, raw = [], {}
    try:
        for row in rows:
            tree = plant(row, base)
            work = base / row["id"] / "work"
            work.mkdir()
            try:
                recs = adapter.scan(tree, work)
            except ScannerTimeout as e:
                # Not a miss: the scanner did not finish, so it neither found nor missed anything.
                raw[row["id"]] = []
                scored.append({"id": row["id"], "axis": row_axis(row, families), "negative": row["negative"],
                               "outcome": ERROR, "error": str(e)})
                continue
            raw[row["id"]] = [r.to_dict() for r in recs]
            s = score_row(row, recs, families)
            if "right_template" in row:
                fix_tree = plant(row, base, fixed=True)
                fix_work = base / row["id"] / "fix-work"
                fix_work.mkdir()
                try:
                    fix_recs = adapter.scan(fix_tree, fix_work)
                    s["fix"] = score_fix(row, fix_recs)
                except ScannerTimeout as e:
                    fix_recs = []
                    s["fix"] = {"id": row["id"], "outcome": ERROR, "error": str(e)}
                raw[row["id"] + "/fix"] = [r.to_dict() for r in fix_recs]
            scored.append(s)
    finally:
        if keep:
            if keep.exists():
                shutil.rmtree(keep)
            shutil.copytree(base, keep)
        shutil.rmtree(base, ignore_errors=True)

    # The headline summary and the by_* tables are the quantum axis only, so adding weak or
    # defect rows never moves them. The other axes are reported apart under "axes".
    # scanner_error rows are counted apart and left out of every n below; "catalogue" keeps
    # the full counts of the catalogue itself.
    quantum = [s for s in scored if s["axis"] == "quantum"]
    pos = [s for s in _scored(quantum) if not s["negative"]]
    neg = [s for s in _scored(quantum) if s["negative"]]
    errors = _errors(scored)
    counts = lambda xs, o: sum(s["outcome"] == o for s in xs)  # noqa: E731
    cat_sha = catalogue_sha256(root)
    version = catalogue_version(root)
    m, la = counts(pos, "hit"), counts(neg, "false_alarm")
    return {
        "result_format": RESULT_FORMAT,
        "catalogue": {"name": "ShorList", "version": version, "sha256": cat_sha,
                      "rows": len(rows), "positive": sum(not s["negative"] for s in quantum),
                      "decoys": sum(s["negative"] for s in quantum),
                      "by_axis": {a: sum(s["axis"] == a for s in scored) for a in ("quantum", "weak", "defect")}},
        "generator": {"name": "shorlist", "version": __version__},
        "scanner": {"adapter": adapter.name, "command": adapter.command, "version": scanner_version},
        "summary": {
            "statement": (f"Of {len(pos)} positive forms in ShorList {version}, {scanner_version} recognises "
                          f"{m}; of {len(neg)} decoys it reports {la} as a use. This measures recognition of "
                          f"a form in a minimal context; it is not recall and not finding in a real tree."
                          + (f" {errors['n']} row(s) not scored (scanner_error) and left out of these "
                             f"figures: {', '.join(errors['ids'])}." if errors["n"] else "")),
            "positive": {o: counts(pos, o) for o in POSITIVE} | {"n": len(pos)},
            "decoys": {o: counts(neg, o) for o in ("ok", "false_alarm")} | {"n": len(neg)},
            "role_ok": {"true": sum(s["role_ok"] is True for s in pos), "false": sum(s["role_ok"] is False for s in pos)},
            "size_ok": {"true": sum(s["size_ok"] is True for s in pos), "false": sum(s["size_ok"] is False for s in pos)},
            "scanner_error": _errors(quantum),
        },
        "scanner_error": errors,
        "axes": _axes(scored),
        "by_form_kind": _table(quantum, rows_by_id, "form_kind"),
        "by_family": _table(quantum, rows_by_id, "family"),
        "by_language_or_product": _table(quantum, rows_by_id, "language_or_product"),
        "rows": scored,
        "fingerprint": fingerprint(cat_sha, __version__, scanner_version, scored),
        "fingerprint_rule": "sha256(canonical JSON {catalogue_sha256, generator_version, scanner_version, rows:[[id,outcome,role_ok,size_ok]...]})",
        "run": {  # not part of the fingerprint
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": platform.python_version(), "platform": platform.platform(),
        },
        "raw_records": raw,
    }


def markdown(result: dict) -> str:
    """Human-readable tables for a result."""
    L = [f"**{result['summary']['statement']}**", "",
         f"catalogue {result['catalogue']['version']} sha256 `{result['catalogue']['sha256'][:16]}…` · "
         f"generator {result['generator']['version']} · fingerprint `{result['fingerprint'][:16]}…`", ""]
    p, d = result["summary"]["positive"], result["summary"]["decoys"]
    L += ["| positive forms | hit | parent only | wrong family | file only (no line; not a hit) | miss | decoys | ok | false alarm |",
          "|---|---|---|---|---|---|---|---|---|",
          f"| {p['n']} | {p['hit']} | {p['parent_only']} | {p['wrong_family']} | {p.get('file_only', 0)} | {p['miss']} | {d['n']} | {d['ok']} | {d['false_alarm']} |", ""]
    err = result.get("scanner_error", {"n": 0})
    if err["n"]:
        L += [f"**{err['n']} row(s) not scored (scanner_error)**, left out of every figure: {', '.join(err['ids'])}", ""]
    for key, title in (("by_form_kind", "form_kind"), ("by_family", "family"), ("by_language_or_product", "language / product")):
        L += [f"| {title} | positive: hit / n | file only | decoys: false alarm / n |", "|---|---|---|---|"]
        for k, c in result[key].items():
            L.append(f"| {k} | {c['hit']} / {c['positive']} | {c.get('file_only', 0)} | {c['false_alarm']} / {c['decoys']} |")
        L.append("")
    for axis, a in result.get("axes", {}).items():
        p, d = a["positive"], a["decoys"]
        if a.get("scanner_error", {}).get("n"):
            L += [f"{axis} axis: {a['scanner_error']['n']} row(s) not scored (scanner_error): {', '.join(a['scanner_error']['ids'])}", ""]
        L += [f"**{axis} axis** (scored apart; not in the figures above)", "",
              "| positive | " + " | ".join(k for k in p if k != "n") + " | decoys | ok | false alarm |" + (" fixed files | false alarm |" if "fixed_files" in a else ""),
              "|" + "---|" * (len(p) + 3 + (2 if "fixed_files" in a else 0)),
              f"| {p['n']} | " + " | ".join(str(v) for k, v in p.items() if k != "n") + f" | {d['n']} | {d['ok']} | {d['false_alarm']} |"
              + (f" {a['fixed_files']['n']} | {a['fixed_files']['false_alarm']} |" if "fixed_files" in a else ""), ""]
    L += ["| id | decoy | outcome | reported as use | reported as not-use | role ok | size ok |", "|---|---|---|---|---|---|---|"]
    fmt = lambda v: "—" if v is None else ("yes" if v else "no")  # noqa: E731
    for s in result["rows"]:
        if s["outcome"] == ERROR:
            L.append(f"| {s['id']} | {'yes' if s['negative'] else ''} | {ERROR} | — | — | — | — |")
            continue
        if s["axis"] == "defect":
            fix = f"; fixed file: {s['fix']['outcome']}" if "fix" in s else ""
            L.append(f"| {s['id']} | {'yes' if s['negative'] else ''} | {s['outcome']}{fix} | {', '.join(s['reported_cwe']) or '—'} | — | — | — |")
            continue
        L.append(f"| {s['id']} | {'yes' if s['negative'] else ''} | {s['outcome']} | {', '.join(s['reported_as_use']) or '—'} | "
                 f"{', '.join(s['reported_not_use']) or '—'} | {fmt(s.get('role_ok'))} | {fmt(s.get('size_ok'))} |")
    return "\n".join(L) + "\n"
