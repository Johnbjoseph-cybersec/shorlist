"""The adapter interface.

An adapter is constructed with the command that starts the scanner (a list of argv words,
e.g. ["qrp-mcp"] or ["uvx", "qrp-mcp@0.44.0"]) and implements two methods:

    version() -> str
        The scanner's own version string, as the scanner reports it. Goes into the result
        and into the fingerprint.

    scan(tree: Path, workdir: Path) -> list[Record]
        Scan the directory `tree` (one planted row) and return every finding as a Record.
        `workdir` is a private scratch directory for output files. No network.

Record fields:
    path    file path relative to `tree`, POSIX separators
    line    1-based line number, or None when the scanner reports none
    family  a family from schema/families.yaml, or the scanner's own name when it has no
            equivalent there (the scorer ignores names outside the vocabulary)
    role    "signature" | "key_establishment" | "both" | "undetermined" | None
    size    int | "undetermined" | None
    is_use  True when the scanner reports the text as a USE of the algorithm; False when
            it reports it but marks it as not a use (comment, ban, removal, mention).
            A scanner with no such distinction returns True for everything.
    cwe     "CWE-NNN" when the scanner reports a misuse (defect axis), else None

The adapter is the only place that knows a scanner's field names and family spellings.

scan() raises ScannerTimeout when the scanner did not finish on a row (after its retry); the
generator then records that row as `scanner_error` and goes on with the next one.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


class ScannerTimeout(RuntimeError):
    """The scanner did not finish on one row. The row is recorded as scanner_error, not scored."""


@dataclass(frozen=True)
class Record:
    path: str
    line: int | None
    family: str
    role: str | None = None
    size: int | str | None = None
    is_use: bool = True
    cwe: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class Adapter:
    name: str = "base"
    default_command: list[str] = []

    def __init__(self, command: list[str] | None = None):
        self.command = list(command or self.default_command)

    def version(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def scan(self, tree: Path, workdir: Path) -> list[Record]:  # pragma: no cover - interface
        raise NotImplementedError
