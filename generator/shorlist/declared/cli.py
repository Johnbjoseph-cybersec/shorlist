"""`python -m shorlist declared ...`"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import rows as rowsmod
from .adapters import TOOLS


def add_parser(sub) -> None:
    p = sub.add_parser("declared", help="declaration axis: a supplier CBOM against a listener's accepted set")
    p.add_argument("--adapter", action="append", choices=sorted(TOOLS),
                   help="tool to score (repeat for several; 'reference' is the positive control, not a scanner)")
    p.add_argument("--out-dir", type=Path, help="write <adapter>.json and <adapter>.md here")
    p.add_argument("--rows", help="comma-separated row ids (default: all)")
    p.add_argument("--keep", type=Path, help="keep each tool's raw stdout/stderr per row here")
    p.add_argument("--validate", action="store_true", help="validate rows, listeners and observations, then exit")
    p.add_argument("--stats", action="store_true", help="print row statistics and exit")
    p.add_argument("--capture", action="store_true", help="capture the listeners' accepted sets (docker), then exit")
    p.add_argument("--listeners", help="with --capture: comma-separated listener ids (default: all)")
    p.add_argument("--table", type=Path, help="print the Markdown tables of a result file and exit")
    p.set_defaults(f=cmd_declared)


def cmd_declared(args) -> int:
    from . import scoring
    if args.table:
        print(scoring.markdown(json.loads(args.table.read_text())))
        return 0
    if args.stats:
        print(json.dumps(rowsmod.stats(), indent=1))
        return 0
    if args.validate:
        errs = rowsmod.problems()
        st = rowsmod.stats()
        print("\n".join(errs))
        print(f"{st['rows']} declaration rows ({st['not_scored']} not scored), {st['listeners']} listeners; {len(errs)} problems")
        return 1 if errs else 0
    if args.capture:
        from .capture import Capture
        only = set(args.listeners.split(",")) if args.listeners else None
        Capture(log=lambda m: print(m, flush=True)).go(rowsmod.listeners(), rowsmod.OBS, only)
        return 0
    if not args.adapter:
        print("declared: --adapter is required for a run", file=sys.stderr)
        return 2
    from .run import run
    only = set(args.rows.split(",")) if args.rows else None
    rc = 0
    for name in args.adapter:
        res = run(name, keep=args.keep / name if args.keep else None, only=only, log=lambda m: print(m, flush=True))
        md = scoring.markdown(res)
        if args.out_dir:
            args.out_dir.mkdir(parents=True, exist_ok=True)
            stem = args.out_dir / name
            Path(f"{stem}.json").write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n")
            Path(f"{stem}.md").write_text(md + "\n")
        print(md)
        if res.get("control_passed") is False:
            rc = 1
    return rc
