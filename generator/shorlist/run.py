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

RESULT_FORMAT = "0.1"


def plant(row: dict, base: Path) -> Path:
    tree = base / row["id"] / "tree"
    tree.mkdir(parents=True)
    (tree / row["context_filename"]).write_text(row["context_template"])
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


def fingerprint(cat_sha: str, gen_version: str, scanner_version: str, scored: list[dict]) -> str:
    """sha256 of the canonical JSON of catalogue sha, generator version, scanner version and
    the ordered per-row (id, outcome, role_ok, size_ok)."""
    body = {
        "catalogue_sha256": cat_sha,
        "generator_version": gen_version,
        "scanner_version": scanner_version,
        "rows": [[s["id"], s["outcome"], s.get("role_ok"), s.get("size_ok")] for s in scored],
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run(adapter: Adapter, root: Path = ROOT, keep: Path | None = None) -> dict:
    from .score import score_row

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
            recs = adapter.scan(tree, work)
            raw[row["id"]] = [r.to_dict() for r in recs]
            scored.append(score_row(row, recs, families))
    finally:
        if keep:
            if keep.exists():
                shutil.rmtree(keep)
            shutil.copytree(base, keep)
        shutil.rmtree(base, ignore_errors=True)

    pos = [s for s in scored if not s["negative"]]
    neg = [s for s in scored if s["negative"]]
    counts = lambda xs, o: sum(s["outcome"] == o for s in xs)  # noqa: E731
    cat_sha = catalogue_sha256(root)
    version = catalogue_version(root)
    m, la = counts(pos, "hit"), counts(neg, "false_alarm")
    return {
        "result_format": RESULT_FORMAT,
        "catalogue": {"name": "ShorList", "version": version, "sha256": cat_sha,
                      "rows": len(rows), "positive": len(pos), "decoys": len(neg)},
        "generator": {"name": "shorlist", "version": __version__},
        "scanner": {"adapter": adapter.name, "command": adapter.command, "version": scanner_version},
        "summary": {
            "statement": (f"Of {len(pos)} positive forms in ShorList {version}, {scanner_version} recognises "
                          f"{m}; of {len(neg)} decoys it reports {la} as a use. This measures recognition of "
                          f"a form in a minimal context; it is not recall and not finding in a real tree."),
            "positive": {o: counts(pos, o) for o in ("hit", "parent_only", "wrong_family", "miss")} | {"n": len(pos)},
            "decoys": {o: counts(neg, o) for o in ("ok", "false_alarm")} | {"n": len(neg)},
            "role_ok": {"true": sum(s["role_ok"] is True for s in pos), "false": sum(s["role_ok"] is False for s in pos)},
            "size_ok": {"true": sum(s["size_ok"] is True for s in pos), "false": sum(s["size_ok"] is False for s in pos)},
        },
        "by_form_kind": _table(scored, rows_by_id, "form_kind"),
        "by_family": _table(scored, rows_by_id, "family"),
        "by_language_or_product": _table(scored, rows_by_id, "language_or_product"),
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
    L += ["| positive forms | hit | parent only | wrong family | miss | decoys | ok | false alarm |",
          "|---|---|---|---|---|---|---|---|",
          f"| {p['n']} | {p['hit']} | {p['parent_only']} | {p['wrong_family']} | {p['miss']} | {d['n']} | {d['ok']} | {d['false_alarm']} |", ""]
    for key, title in (("by_form_kind", "form_kind"), ("by_family", "family"), ("by_language_or_product", "language / product")):
        L += [f"| {title} | positive: hit / n | decoys: false alarm / n |", "|---|---|---|"]
        for k, c in result[key].items():
            L.append(f"| {k} | {c['hit']} / {c['positive']} | {c['false_alarm']} / {c['decoys']} |")
        L.append("")
    L += ["| id | decoy | outcome | reported as use | reported as not-use | role ok | size ok |", "|---|---|---|---|---|---|---|"]
    fmt = lambda v: "—" if v is None else ("yes" if v else "no")  # noqa: E731
    for s in result["rows"]:
        L.append(f"| {s['id']} | {'yes' if s['negative'] else ''} | {s['outcome']} | {', '.join(s['reported_as_use']) or '—'} | "
                 f"{', '.join(s['reported_not_use']) or '—'} | {fmt(s.get('role_ok'))} | {fmt(s.get('size_ok'))} |")
    return "\n".join(L) + "\n"
