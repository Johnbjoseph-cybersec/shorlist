"""Shared plumbing for scanners that run in a throwaway container.

The adapter's command is a `docker run` prefix that ends with the image (pin it by image ID or
digest), for example:

    docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges
        --memory 1g --cpus 1 --pids-limit 512 --tmpfs /tmp:rw,size=512m <image>

At scan time two mounts are inserted right after `run`, and nothing else:

    <tree>   -> /scan  read-only   (the planted row)
    <outdir> -> /out   read-write  (the scanner's output files)

so the command recorded in a result carries no host path. `outdir` is
$SHORLIST_OUT_DIR/<row id> when that variable is set (<row id>-fix for the fixed file of a
defect row, which run.plant() writes to <row id>/fix), else the generator's private workdir.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .base import Adapter

ANSI = re.compile(r"\x1b\[[0-9;]*m")
SCAN, OUT = "/scan", "/out"


def default_command(image: str) -> list[str]:
    return ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", "1g", "--cpus", "1",
            "--pids-limit", "512", "--tmpfs", "/tmp:rw,size=512m", image]


class ContainerAdapter(Adapter):
    image: str = ""

    def __init__(self, command: list[str] | None = None):
        super().__init__(command or default_command(self.image))
        if self.command[:2] != ["docker", "run"]:
            raise ValueError(f"{self.name}: the command must be a 'docker run ... <image>' prefix")

    def _argv(self, args: list[str], entrypoint: str | None, mounts: list[str]) -> list[str]:
        ep = ["--entrypoint", entrypoint] if entrypoint else []
        return self.command[:2] + mounts + self.command[2:-1] + ep + [self.command[-1]] + args

    def run_plain(self, args: list[str], entrypoint: str | None = None, timeout: int = 300) -> str:
        """Run without mounts (version queries). Returns stdout+stderr with colour codes removed."""
        p = subprocess.run(self._argv(args, entrypoint, []), capture_output=True, text=True, timeout=timeout)
        return ANSI.sub("", (p.stdout or "") + (p.stderr or ""))

    def outdir(self, tree: Path, workdir: Path) -> Path:
        base = os.environ.get("SHORLIST_OUT_DIR")
        name = tree.parent.name + ("-fix" if tree.name == "fix" else "")
        d = Path(base) / name if base else workdir / "out"
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o777)  # the scanners run as a non-root user
        return d

    def run_scan(self, tree: Path, outdir: Path, args: list[str], entrypoint: str | None = None,
                 timeout: int = 900) -> subprocess.CompletedProcess:
        mounts = ["-v", f"{tree.resolve()}:{SCAN}:ro", "-v", f"{outdir.resolve()}:{OUT}"]
        p = subprocess.run(self._argv(args, entrypoint, mounts), capture_output=True, text=True, timeout=timeout)
        (outdir / "stderr.txt").write_text(ANSI.sub("", p.stderr or ""))
        (outdir / "exit_code.txt").write_text(f"{p.returncode}\n")
        return p


def rel_path(location: str) -> str:
    """A location as the scanner wrote it -> path relative to the planted tree ('' if outside it)."""
    loc = str(location).replace("\\", "/")
    if loc.startswith("file://"):
        loc = loc[len("file://"):]
    if loc.startswith(SCAN + "/"):
        return loc[len(SCAN) + 1:]
    if loc.startswith("/"):
        return ""  # an absolute path outside /scan: not in the planted tree
    return loc[2:] if loc.startswith("./") else loc
