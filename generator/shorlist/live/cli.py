"""`python -m shorlist live ...`"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import scoring, wire as wiremod
from .scanners import SCANNERS


def add_parser(sub) -> None:
    p = sub.add_parser("live", help="network axis: plant rows as live servers and run network scanners")
    p.add_argument("--adapter", action="append", choices=sorted(SCANNERS),
                   help="scanner to run (repeat for several; one result file each)")
    p.add_argument("--rows", help="comma-separated row ids (default: every runnable row)")
    p.add_argument("--server", help="comma-separated servers: openssh,nginx,apache,s_server")
    p.add_argument("--out-dir", type=Path, help="write <adapter>.json and <adapter>.md here")
    p.add_argument("--timeout", type=int, default=300, help="seconds per scanner container (default 300)")
    p.add_argument("--keep", type=Path, help="copy the planted configs, reference output and raw scanner output here")
    p.add_argument("--stats", action="store_true", help="print wire.yaml statistics and exit")
    p.add_argument("--table", type=Path, help="print the Markdown tables of a result file and exit")
    p.set_defaults(f=cmd_live)


def cmd_live(args) -> int:
    if args.stats:
        print(json.dumps(wiremod.stats(wiremod.load()), indent=1))
        return 0
    if args.table:
        print(scoring.markdown(json.loads(args.table.read_text())))
        return 0
    if not args.adapter or not args.out_dir:
        print("live: --adapter and --out-dir are required for a run", file=sys.stderr)
        return 2
    from .harness import Run
    only = set(args.rows.split(",")) if args.rows else None
    server = set(args.server.split(",")) if args.server else None
    results = Run(args.adapter, timeout=args.timeout, keep=args.keep,
                  log=lambda m: print(m, flush=True)).go(args.root, only, server)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for res in results:
        stem = args.out_dir / res["scanner"]["adapter"]  # "testssl.sh" -> testssl.sh.json, not testssl.json
        Path(f"{stem}.json").write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
        md = scoring.markdown(res)
        Path(f"{stem}.md").write_text(md)
        print(md.split("\n\n")[0])
        print(f"  -> {stem}.json / .md")
    return 0
