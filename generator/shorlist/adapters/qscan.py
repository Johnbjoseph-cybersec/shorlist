"""Adapter for qscan (https://github.com/EthanCratchley/qscan), installed from that repository.

Not the PyPI package named "qscan", which is an unrelated project
(https://gitlab.com/astroquasar/programs/qscan); the image installs from GitHub at a commit.

Output read: the CycloneDX 1.6 CBOM of `qscan scan <dir> --format cbom`, documented in
docs/cbom-format.md (https://github.com/EthanCratchley/qscan/blob/8b737992ef65cb8e97e343b2d2bbd1a5eee7d4ef/docs/cbom-format.md).
The JSON format has no field reference, so it is not used.

Mapping:
- one Record per `cryptographic-asset` component; path and line from the properties
  `qscan:filePath` and `qscan:lineNumber` ("Custom Properties");
- family from algorithmFamily/name via schema/families.yaml (shared rules in _cyclonedx.py);
- role from primitive (signature / kem / key-agree), else None. qscan writes `pke` for RSA,
  ECC and ECDSA alike ("CryptoPrimitive" table), so those carry no role;
- size: algorithmProperties.parameterSetIdentifier, documented as the finding's key_size
  ("Parameter Set Identifier");
- is_use: True; the CBOM has no not-a-use marker.

Invocation: default settings; no --triage (that needs an OpenRouter key and the network).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import _cyclonedx
from ._container import OUT, SCAN, ContainerAdapter, rel_path
from .base import Record


def _locations(c: dict) -> list[tuple[str, int | None]]:
    props = {p.get("name"): p.get("value") for p in c.get("properties") or []}
    path = rel_path(props.get("qscan:filePath") or "")
    line = props.get("qscan:lineNumber")
    if not path:
        return []
    return [(path, int(line) if line is not None and str(line).isdigit() else None)]


class QscanAdapter(ContainerAdapter):
    name = "qscan"
    image = "shorlist-qscan:1.0.0"

    def version(self) -> str:
        m = re.search(r"qscan\s+(\S+)", self.run_plain(["version"]))
        return f"qscan {m.group(1)}" if m else "qscan unknown"

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = self.outdir(tree, workdir)
        p = self.run_scan(tree, out, ["scan", SCAN, "--format", "cbom", "--output", f"{OUT}/cbom.json"])
        f = out / "cbom.json"
        if not f.exists():
            raise RuntimeError(f"qscan wrote no CBOM (exit {p.returncode}): {p.stderr.strip()[-500:]}")
        return self.parse(json.loads(f.read_text()))

    @staticmethod
    def parse(bom: dict) -> list[Record]:
        return _cyclonedx.records(bom, size_from_parameter_set=True, locations=_locations)
