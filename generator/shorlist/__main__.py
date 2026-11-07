"""Command line.

    python -m shorlist validate               schema + template syntax for every row
    python -m shorlist run --adapter qrp-mcp [--command "uvx qrp-mcp@0.44.0"] --out result.json [--md result.md]
    python -m shorlist table result.json      print the Markdown tables of a result
    python -m shorlist live --adapter ssh-audit --out-dir ../results/live   network axis (live servers)
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
from .parsecheck import FAIL, check
from .run import markdown, run


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
    result = run(adapter, args.root, keep=args.keep_trees)
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
    r.set_defaults(f=cmd_run)
    t = sub.add_parser("table")
    t.add_argument("result")
    t.set_defaults(f=cmd_table)
    live_cli.add_parser(sub)
    args = ap.parse_args(argv)
    return args.f(args)


if __name__ == "__main__":
    sys.exit(main())
