"""Load, validate and hash the catalogue (forms/*.yaml)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]


def load_schema(root: Path = ROOT) -> dict:
    return json.loads((root / "schema" / "form.schema.json").read_text())


def load_families(root: Path = ROOT) -> dict[str, dict]:
    """Family name -> {cyclonedx: [...], parent: str|None, role: str|None}."""
    data = yaml.safe_load((root / "schema" / "families.yaml").read_text())
    out: dict[str, dict] = {}
    for group in data.values():
        for name, spec in group.items():
            out[name] = {"cyclonedx": spec.get("cyclonedx", []), "parent": spec.get("parent"),
                         "role": spec.get("role")}
    return out


def catalogue_version(root: Path = ROOT) -> str:
    return (root / "VERSION").read_text().strip()


def form_files(root: Path = ROOT) -> list[Path]:
    return sorted((root / "forms").glob("*.yaml"))


def catalogue_sha256(root: Path = ROOT) -> str:
    """sha256 over, for each forms/*.yaml in sorted path order: path, NUL, bytes, NUL."""
    h = hashlib.sha256()
    for p in form_files(root):
        h.update(p.relative_to(root).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def literal_line(row: dict) -> int:
    """1-based line of the template on which the literal stands (first occurrence)."""
    for i, line in enumerate(row["context_template"].split("\n"), start=1):
        if row["literal"] in line:
            return i
    raise ValueError(f"{row['id']}: literal not found in context_template")


def validate_row(row: dict, path: Path | None, schema: dict, families: dict) -> list[str]:
    """Schema errors plus the checks a schema cannot express."""
    v = Draft202012Validator(schema, format_checker=FormatChecker())
    errs = [f"{'/'.join(map(str, e.absolute_path)) or '<row>'}: {e.message}" for e in v.iter_errors(row)]
    if errs:
        return errs
    if path is not None and path.stem != row["id"]:
        errs.append(f"file name {path.name} does not match id {row['id']}")
    if row["literal"] not in row["context_template"]:
        errs.append("literal does not occur verbatim in context_template")
    cdx = row.get("cyclonedx_family")
    if cdx is not None and cdx not in families[row["family"]]["cyclonedx"]:
        errs.append(f"cyclonedx_family {cdx!r} is not mapped from family {row['family']} in families.yaml")
    if row["expected"]["family"] != row["family"]:
        errs.append("expected.family differs from family")
    return errs


def load(root: Path = ROOT, *, include_withdrawn: bool = False) -> list[dict]:
    """Load and validate every row; raise ValueError listing all problems."""
    schema, families = load_schema(root), load_families(root)
    enum = set(schema["$defs"]["family"]["enum"])
    if enum != set(families):
        raise ValueError(f"schema family enum and families.yaml differ: {sorted(enum ^ set(families))}")
    rows, problems, seen = [], [], set()
    for p in form_files(root):
        row = yaml.safe_load(p.read_text())
        for e in validate_row(row, p, schema, families):
            problems.append(f"{p.name}: {e}")
        rid = row.get("id") if isinstance(row, dict) else None
        if rid in seen:
            problems.append(f"{p.name}: duplicate id {rid}")
        seen.add(rid)
        rows.append(row)
    if problems:
        raise ValueError("catalogue invalid:\n  " + "\n  ".join(problems))
    if not include_withdrawn:
        rows = [r for r in rows if r["status"] != "withdrawn"]
    return rows
