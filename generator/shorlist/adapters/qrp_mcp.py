"""Adapter for qrp-mcp (https://github.com/StanimirTenev/qrp-mcp), `qrp-mcp scan --out`.

Mapping:
- every item in every list under `evidence` that carries an `algorithm` becomes a Record
  (items with `algorithm: null`, e.g. bare protocol rows, are skipped);
- `is_use` is False when `evidence_kind` is one of {comment, ban, named_but_not_used,
  identifier}: the set qrp-mcp itself treats as "not a use" (src/qrp_mcp/mandates.py,
  `_NOT_USE`, at 0.44.0);
- family spellings: Ed25519/Ed448 -> EdDSA, FFDH -> DH; others pass through;
- an item with no `role` in a category qrp-mcp treats as key establishment by what it is
  (tls_groups, ssh_kex, static_rsa_kex; mandates.py `_KEY_ESTABLISHMENT`) gets that role.

The scan runs with --no-config (a config file in the planted tree must not change the
result) and --level full. qrp-mcp may exit non-zero while writing a valid result (a gate);
the result file is read regardless of the exit code.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .base import Adapter, Record

NOT_USE = {"comment", "ban", "named_but_not_used", "identifier"}
FAMILY_MAP = {"Ed25519": "EdDSA", "Ed448": "EdDSA", "FFDH": "DH"}
KEY_ESTABLISHMENT_CATEGORIES = {"tls_groups", "ssh_kex", "static_rsa_kex"}


class QrpMcpAdapter(Adapter):
    name = "qrp-mcp"
    default_command = ["qrp-mcp"]

    def version(self) -> str:
        p = subprocess.run(self.command + ["--version"], capture_output=True, text=True, timeout=300)
        return (p.stdout or p.stderr).strip()

    def scan(self, tree: Path, workdir: Path) -> list[Record]:
        out = workdir / "qrp-mcp.json"
        p = subprocess.run(
            self.command + ["scan", str(tree), "--no-config", "--level", "full", "--out", str(out)],
            capture_output=True, text=True, timeout=600,
        )
        if not out.exists():
            raise RuntimeError(f"qrp-mcp wrote no result (exit {p.returncode}): {p.stderr.strip()[:500]}")
        return self.parse(json.loads(out.read_text()))

    @staticmethod
    def parse(result: dict) -> list[Record]:
        recs = []
        for category, items in (result.get("evidence") or {}).items():
            for e in items or []:
                alg = e.get("algorithm")
                if not alg:
                    continue
                recs.append(Record(
                    path=str(e.get("path", "")).replace("\\", "/"),
                    line=e.get("line"),
                    family=FAMILY_MAP.get(alg, alg),
                    role=e.get("role") or ("key_establishment" if category in KEY_ESTABLISHMENT_CATEGORIES else None),
                    size=e.get("key_size"),
                    is_use=e.get("evidence_kind") not in NOT_USE,
                ))
        return recs
