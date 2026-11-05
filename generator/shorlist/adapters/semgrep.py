"""Adapter for Semgrep Community Edition (https://github.com/semgrep/semgrep) with the public
crypto rules of https://github.com/semgrep/semgrep-rules.

Ruleset: every rule file under a directory of semgrep-rules whose path contains "crypt"
(case-insensitive), test fixtures excluded, at the commit baked into the image (written to
/rules/VERSION). The rule files are not part of this repository (Semgrep Rules License v1.0).
The selection was fixed before the first scan. A registry ruleset (`--config p/...`) cannot be
used, because the scan runs with no network.

Output read: `semgrep scan --json`, the CLI JSON output (https://semgrep.dev/docs/cli-reference,
schema: semgrep-interfaces semgrep_output_v1): results[].check_id, .path, .start.line.

Mapping:
- one Record per result, at (path, start.line);
- family: Semgrep results carry no algorithm field. The family is taken from the tokens of
  `check_id` (split on . - _): a token equal, case-insensitively, to a family name or one of its
  CycloneDX names in schema/families.yaml (e.g. "...insufficient-rsa-key-size" -> RSA). A
  result with no such token keeps its check_id as family, which the scorer ignores;
- role and size: None, not in the output;
- is_use: True; Semgrep reports matches, not uses.

Invocation: --metrics=off --disable-version-check.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ._container import OUT, SCAN, ContainerAdapter, rel_path
from ._cyclonedx import VOCAB
from .base import Record


def family_from_check_id(check_id: str) -> str:
    for tok in re.split(r"[._-]", check_id):
        fam = VOCAB.get(tok.upper())
        if fam:
            return fam
    return check_id


class SemgrepAdapter(ContainerAdapter):
    name = "semgrep"
    image = "shorlist-semgrep:1.183.0"

    def version(self) -> str:
        v = self.run_plain(["--version", "--disable-version-check"]).strip().splitlines()[-1].strip()
        rules = self.run_plain(["/rules/VERSION"], entrypoint="cat").strip()
        return f"semgrep {v} + {rules}"

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = self.outdir(tree, workdir)
        p = self.run_scan(tree, out, ["scan", "--config", "/rules", "--metrics=off", "--disable-version-check",
                                      "--json", "--output", f"{OUT}/semgrep.json", SCAN])
        f = out / "semgrep.json"
        if not f.exists():
            raise RuntimeError(f"semgrep wrote no result (exit {p.returncode}): {p.stderr.strip()[-500:]}")
        return self.parse(json.loads(f.read_text()))

    @staticmethod
    def parse(result: dict) -> list[Record]:
        return [Record(path=rel_path(r.get("path", "")), line=(r.get("start") or {}).get("line"),
                       family=family_from_check_id(r.get("check_id", "")))
                for r in result.get("results") or [] if rel_path(r.get("path", ""))]
