"""Command line.

    python -m shorlist validate               schema + template syntax for every row
    python -m shorlist run --adapter qrp-mcp [--command "uvx qrp-mcp@0.44.0"] --out result.json [--md result.md]
    python -m shorlist table result.json      print the Markdown tables of a result
    python -m shorlist run ... --shard 3/8    only rows with index 3 mod 8 (a partial result)
    python -m shorlist merge --out result.json [--md result.md] shard-*.json
    python -m shorlist live --adapter ssh-audit --out-dir ../results/live   network axis (live servers)
    python -m shorlist declared --adapter sbom-tools --out-dir ../results/declared   declaration axis
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from .adapters import ADAPTERS
from .catalogue import ROOT, load
from .live import cli as live_cli
from .declared import cli as declared_cli
from .parsecheck import FAIL, check
from .run import markdown, merge, run


def cmd_validate(args) -> int:
    try:
        rows = load(args.root, include_withdrawn=True)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    bad = 0
    for r in rows:
        status, detail = check(r["context_filename"], r["context_template"])
        print(f"{r['id']}  {r['context_filename']:<16} {status}{('  ' + detail) if detail else ''}")
        bad += status == FAIL
        if "right_template" in r:
            status, detail = check(r["context_filename"], r["right_template"])
            print(f"{r['id']}  {'(right) ' + r['context_filename']:<16} {status}{('  ' + detail) if detail else ''}")
            bad += status == FAIL
    print(f"{len(rows)} rows valid against the schema; {bad} template(s) fail the syntax check")
    return 1 if bad else 0


def cmd_run(args) -> int:
    adapter = ADAPTERS[args.adapter](shlex.split(args.command) if args.command else None)
    shard = tuple(int(x) for x in args.shard.split("/")) if args.shard else None
    if shard and not 0 <= shard[0] < shard[1]:
        raise SystemExit("--shard I/N needs 0 <= I < N")
    result = run(adapter, args.root, keep=args.keep_trees, shard=shard)
    Path(args.out).write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    if shard:
        print(f"shard {shard[0]}/{shard[1]}: {len(result['rows'])} rows")
        return 0
    md = markdown(result)
    if args.md:
        Path(args.md).write_text(md)
    print(md)
    return 0


def cmd_merge(args) -> int:
    result = merge([json.loads(Path(f).read_text()) for f in args.shards], args.root)
    Path(args.out).write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    md = markdown(result)
    if args.md:
        Path(args.md).write_text(md)
    print(md)
    return 0


def cmd_table(args) -> int:
    print(markdown(json.loads(Path(args.result).read_text())))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="shorlist")
    ap.add_argument("--root", type=Path, default=ROOT, help="catalogue root (default: this repository)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate").set_defaults(f=cmd_validate)
    r = sub.add_parser("run")
    r.add_argument("--adapter", required=True, choices=sorted(ADAPTERS))
    r.add_argument("--command", help="scanner command line, e.g. 'uvx qrp-mcp@0.44.0' (default: the adapter's)")
    r.add_argument("--out", required=True)
    r.add_argument("--md")
    r.add_argument("--keep-trees", type=Path, help="copy the planted trees and raw outputs here")
    r.add_argument("--shard", help="I/N: scan only the rows whose index is I mod N; join with merge")
    r.set_defaults(f=cmd_run)
    g = sub.add_parser("merge")
    g.add_argument("--out", required=True)
    g.add_argument("--md")
    g.add_argument("shards", nargs="+")
    g.set_defaults(f=cmd_merge)
    t = sub.add_parser("table")
    t.add_argument("result")
    t.set_defaults(f=cmd_table)
    live_cli.add_parser(sub)
    declared_cli.add_parser(sub)
    args = ap.parse_args(argv)
    return args.f(args)


if __name__ == "__main__":
    sys.exit(main())
