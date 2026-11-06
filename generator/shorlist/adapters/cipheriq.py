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
relatedCryptoMaterialProperties.size; is_use True. cwe: None; cbom-generator writes no CWE (none
in its README, no "cwe" string in the 1.9.3 binary or its plugins, none in its CBOMs of the
weak and defect rows of v0.2).

Two invocations, two adapter names, two result files:
- `cipheriq-cbom-generator`: README "Usage", `cbom-generator --output cbom.json <dirs>`;
- `cipheriq-cbom-generator-services`: README "Service Discovery with YAML Plugins", the
  invocation it documents for service configuration files:
  `--discover-services --plugin-dir /usr/local/share/cbom-generator/plugins/ubuntu
  --cyclonedx-spec=1.7 --output ... <dirs>`. The plugins find a service by absolute paths in the
  scanned system (plugins/ubuntu/nginx.yaml: binary /usr/sbin/nginx `required: true`, config
  /etc/nginx/nginx.conf), not under the directory given on the command line. The planted tree
  is not moved to those paths: that would be setting the tool up for the catalogue.
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


class CipherIQServicesAdapter(CipherIQAdapter):
    name = "cipheriq-cbom-generator-services"
    ARGS = ["--discover-services", "--plugin-dir", "/usr/local/share/cbom-generator/plugins/ubuntu",
            "--cyclonedx-spec=1.7"]

    def version(self) -> str:
        return f"{super().version()} (--discover-services, plugins/ubuntu)"

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = self.outdir(tree, workdir)
        p = self.run_scan(tree, out, self.ARGS + ["--output", f"{OUT}/cbom.json", SCAN])
        f = out / "cbom.json"
        if not f.exists():
            raise RuntimeError(f"cbom-generator wrote no CBOM (exit {p.returncode}): {p.stderr.strip()[-500:]}")
        if "Cannot open YAML file" in (p.stderr or "") + (p.stdout or ""):
            raise RuntimeError("cbom-generator could not read some of its plugins; check the image's file modes")
        return self.parse(json.loads(f.read_text()))
