"""Adapter for CipherIQ cbom-generator (https://github.com/CipherIQ/cbom-generator).

cbom-generator scans a Linux file system for certificates, keys, binaries, libraries and
service configuration, and writes a CycloneDX 1.6 CBOM (README, "Usage": `cbom-generator
--output cbom.json <dirs>`).

Mapping (shared CycloneDX rules in _cyclonedx.py): one Record per
components[].evidence.occurrences[] inside the planted tree. Components that carry no location
in the tree give no Record. This matters here: run on an empty directory, cbom-generator still
lists algorithms and libraries from the container's own installed packages (RSA, ECDSA,
libssl3t64, …) with no location; those describe the scanner's environment, not the planted
row, and are dropped. Family from name via schema/families.yaml; role from primitive; size from
relatedCryptoMaterialProperties.size; is_use True.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import _cyclonedx
from ._container import OUT, SCAN, ContainerAdapter
from .base import Record


class CipherIQAdapter(ContainerAdapter):
    name = "cipheriq-cbom-generator"
    image = "shorlist-cipheriq:1.9.3"

    def version(self) -> str:
        return self.run_plain(["--version"]).strip().splitlines()[0].strip()

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = self.outdir(tree, workdir)
        p = self.run_scan(tree, out, ["--output", f"{OUT}/cbom.json", SCAN])
        f = out / "cbom.json"
        if not f.exists():
            raise RuntimeError(f"cbom-generator wrote no CBOM (exit {p.returncode}): {p.stderr.strip()[-500:]}")
        return self.parse(json.loads(f.read_text()))

    @staticmethod
    def parse(bom: dict) -> list[Record]:
        return _cyclonedx.records(bom)
