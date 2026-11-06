"""Adapter for cdxgen (https://github.com/cdxgen/cdxgen), the `cbom` alias, official image.

`cbom` is `cdxgen --include-crypto --evidence --deep --spec-version 1.7` (docs/CLI.md,
"Aliases and entry-point behavior"; docs/ADVANCED.md, "Generate Cryptography Bill of
Materials (CBOM)", at v13.6.0).

Output read: components of type `cryptographic-asset` (ADVANCED.md, "The shape of a
cryptographic-asset component"). Their place in the source is the property
`cdx:crypto:sourceLocation` = "<file>:<line>:<column>"; CycloneDX evidence.occurrences[] is
read too when present. Library components (type `library`) are packages, not algorithms, and
give no Record.

Mapping (shared CycloneDX rules in _cyclonedx.py): family from algorithmProperties.
algorithmFamily, then name, via schema/families.yaml; role from primitive; size None; is_use
True. algorithmFamily is the CycloneDX enum (ADVANCED.md, "`algorithmFamily` (CycloneDX 1.7)"),
whose SHA-1, MD5, MD4, DES, 3DES, RC4, RC2 are the families.yaml names, so no alias is needed.
cwe: None. ADVANCED.md at v13.6.0 names no CWE field for a cryptographic-asset (no "CWE" in
the file); not checked on output, because the image does not start on a CPU without
x86-64-v3 ("Fatal glibc error: CPU does not support x86-64-v3").

Invocation: one fixed command for every row, `cbom -o /out/bom.json /scan`, project type
auto-detected (no per-row -t).
"""
from __future__ import annotations

import json
from pathlib import Path

from . import _cyclonedx
from ._container import OUT, SCAN, ContainerAdapter, rel_path
from .base import Record


def _locations(c: dict) -> list[tuple[str, int | None]]:
    out = list(_cyclonedx.occurrences(c))
    for p in c.get("properties") or []:
        if p.get("name") == "cdx:crypto:sourceLocation":
            parts = str(p.get("value", "")).rsplit(":", 2)
            path = rel_path(parts[0]) if parts else ""
            line = int(parts[1]) if len(parts) == 3 and parts[1].isdigit() else None
            if path:
                out.append((path, line))
    return sorted(set(out), key=lambda t: (t[0], t[1] or 0))


class CdxgenAdapter(ContainerAdapter):
    name = "cdxgen"
    image = "ghcr.io/cdxgen/cdxgen@sha256:d3465b2f6e76406a1a4c884deeaf0e869514c4e35c47e415e055bb44596b73ea"

    def version(self) -> str:
        return self.run_plain(["--version"], entrypoint="cbom").strip().splitlines()[0].strip()

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = self.outdir(tree, workdir)
        p = self.run_scan(tree, out, ["-o", f"{OUT}/bom.json", SCAN], entrypoint="cbom")
        f = out / "bom.json"
        if not f.exists():
            raise RuntimeError(f"cdxgen wrote no BOM (exit {p.returncode}): {p.stderr.strip()[-500:]}")
        return self.parse(json.loads(f.read_text()))

    @staticmethod
    def parse(bom: dict) -> list[Record]:
        return _cyclonedx.records(bom, locations=_locations)
