"""Adapter for CBOMkit-theia (https://github.com/cbomkit/cbomkit-theia), `cbomkit-theia dir`.

theia states that it does not scan source code (README: "CBOMkit-theia does *not* perform
source code scanning"); it looks for certificates, keys, secrets, OpenSSL configuration and,
with --bom, java.security. It writes a CycloneDX 1.6 CBOM to stdout (README, "Running").

Mapping (shared CycloneDX rules in _cyclonedx.py): one Record per
components[].evidence.occurrences[] inside the planted tree; family from algorithmFamily/name
via schema/families.yaml; role from primitive; size from relatedCryptoMaterialProperties.size;
is_use True. Components with no occurrence in the tree give no Record. cwe: None; theia writes
no CWE (none in its README at v1.1.2, no "CWE-<n>" string in the binary, 0 components on the
weak and defect rows of v0.2).

Invocation: default plugins, no --bom (there is no input CBOM to verify). Version: the module
version recorded in the binary at build time (`go version -m`), written to /VERSION in the
image, because the CLI has no version command and its CBOM names its version "edge".
"""
from __future__ import annotations

import json
from pathlib import Path

from . import _cyclonedx
from ._container import SCAN, ContainerAdapter
from .base import Record


class CbomkitTheiaAdapter(ContainerAdapter):
    name = "cbomkit-theia"
    image = "shorlist-theia:1.1.2"

    def version(self) -> str:
        return self.run_plain(["/VERSION"], entrypoint="cat").strip()

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = self.outdir(tree, workdir)
        p = self.run_scan(tree, out, ["dir", SCAN])
        (out / "cbom.json").write_text(p.stdout)
        try:
            bom = json.loads(p.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(f"cbomkit-theia wrote no CBOM (exit {p.returncode}): {p.stderr.strip()[-500:]}")
        return self.parse(bom)

    @staticmethod
    def parse(bom: dict) -> list[Record]:
        return _cyclonedx.records(bom)
