"""Score normalised scanner records against a row's `expected`.

Positive row (negative: false), looking only at records on the literal's line in the
planted file that have is_use = True:
    hit           a record carries expected.family
    parent_only   no hit, but a record carries the family's parent (EC for ECDSA/ECDH)
    wrong_family  no hit or parent, but a record carries another in-scope family
    miss          nothing in scope on that line reported as a use
  role_ok / size_ok are reported beside the outcome and are not part of it. They are
  None when expected.role / expected.size is "undetermined" or there is no hit. A hit
  with no role takes the family's intrinsic role from families.yaml, if it has one.

Decoy row (negative: true), looking at every record in the planted tree:
    false_alarm   any in-scope family reported as a use, anywhere in the tree
    ok            nothing in scope reported as a use (reporting it as not-a-use is fine)

"In scope" depends on the row's axis (catalogue.row_axis), so the axes do not leak:
    quantum   quantum_vulnerable + post_quantum families (a reported AES or MD5 is ignored)
    weak      the quantum families + classically_weak

Defect axis (row_kind: defect) scores the scanner's `cwe`, not the family:
    hit           a record on the literal's line carries defect.cwe
    wrong_class   no hit, but a record on that line carries another CWE
    miss          no CWE reported on that line
  A defect decoy is false_alarm when any CWE is reported anywhere in the tree. The fixed
  file (right_template) is scored apart by score_fix: false_alarm when any CWE is reported.
"""
from __future__ import annotations

from .adapters.base import Record
from .catalogue import literal_line, row_axis

SCOPE = {"quantum": {"quantum"}, "weak": {"quantum", "weak"}}


def score_fix(row: dict, records: list[Record]) -> dict:
    cwes = sorted({r.cwe for r in records if r.cwe})
    return {"id": row["id"], "outcome": "false_alarm" if cwes else "ok", "reported_cwe": cwes}


def _score_defect(row: dict, records: list[Record]) -> dict:
    if row["negative"]:
        cwes = sorted({r.cwe for r in records if r.cwe})
        return {"id": row["id"], "axis": "defect", "negative": True,
                "outcome": "false_alarm" if cwes else "ok", "reported_cwe": cwes}
    line = literal_line(row)
    here = sorted({r.cwe for r in records if r.cwe and r.path == row["context_filename"] and r.line == line})
    want = row["defect"]["cwe"]
    outcome = "hit" if want in here else ("wrong_class" if here else "miss")
    return {"id": row["id"], "axis": "defect", "negative": False, "outcome": outcome,
            "line": line, "reported_cwe": here}


def score_row(row: dict, records: list[Record], families: dict) -> dict:
    axis = row_axis(row, families)
    if axis == "defect":
        return _score_defect(row, records)
    exp = row["expected"]
    fam = exp["family"]
    parent = families[fam]["parent"]
    fname = row["context_filename"]
    in_scope = [r for r in records if r.family in families and families[r.family]["axis"] in SCOPE[axis]]

    if row["negative"]:
        alarms = sorted({r.family for r in in_scope if r.is_use})
        return {
            "id": row["id"], "axis": axis, "negative": True,
            "outcome": "false_alarm" if alarms else "ok",
            "reported_as_use": alarms,
            "reported_not_use": sorted({r.family for r in in_scope if not r.is_use}),
        }

    line = literal_line(row)
    here = [r for r in in_scope if r.path == fname and r.line == line]
    uses = [r for r in here if r.is_use]
    hits = [r for r in uses if r.family == fam]
    if hits:
        outcome = "hit"
    elif parent and any(r.family == parent for r in uses):
        outcome = "parent_only"
    elif uses:
        outcome = "wrong_family"
    else:
        outcome = "miss"

    role_ok = size_ok = None
    if hits:
        if exp["role"] != "undetermined":
            # A scanner's "both" satisfies an expected single role; an expected "both" needs "both".
            accept = {"both"} if exp["role"] == "both" else {exp["role"], "both"}
            role_ok = any((r.role or families[fam]["role"]) in accept for r in hits)
        if exp["size"] != "undetermined":
            size_ok = any(r.size == exp["size"] for r in hits)
    return {
        "id": row["id"], "axis": axis, "negative": False, "outcome": outcome,
        "line": line,
        "reported_as_use": sorted({r.family for r in uses}),
        "reported_not_use": sorted({r.family for r in here if not r.is_use}),
        "role_ok": role_ok, "size_ok": size_ok,
    }
