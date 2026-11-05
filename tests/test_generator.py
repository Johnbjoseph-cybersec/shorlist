import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "generator"))

from shorlist.adapters.base import Adapter, Record  # noqa: E402
from shorlist.adapters.qrp_mcp import QrpMcpAdapter  # noqa: E402
from shorlist.catalogue import literal_line, load, load_families  # noqa: E402
from shorlist.run import fingerprint, markdown, run  # noqa: E402
from shorlist.score import score_row  # noqa: E402

FAMILIES = load_families()
ROWS = {r["id"]: r for r in load()}


class Oracle(Adapter):
    """Reports exactly what each row expects: a use for positives, a not-use for decoys."""
    name = "oracle"

    def version(self):
        return "oracle 1"

    def scan(self, tree, workdir):
        (f,) = list(tree.iterdir())
        row = next(r for r in ROWS.values() if r["context_filename"] == f.name and r["context_template"] == f.read_text())
        e = row["expected"]
        role = None if e["role"] == "undetermined" else e["role"]
        return [Record(f.name, literal_line(row), e["family"], role, e["size"], is_use=not row["negative"])]


class Silent(Adapter):
    name = "silent"

    def version(self):
        return "silent 1"

    def scan(self, tree, workdir):
        return []


class NaiveToken(Adapter):
    """A grep: any line naming a family is a use. Exists to show the decoys can fail a scanner."""
    name = "naive"
    PAT = {"RSA": r"rsa", "ECDSA": r"ecdsa", "ML-KEM": r"ml-?kem"}

    def version(self):
        return "naive 1"

    def scan(self, tree, workdir):
        recs = []
        for f in tree.iterdir():
            for n, line in enumerate(f.read_text().split("\n"), 1):
                for fam, pat in self.PAT.items():
                    if re.search(pat, line, re.I):
                        recs.append(Record(f.name, n, fam))
        return recs


def test_oracle_scores_perfect():
    res = run(Oracle())
    s = res["summary"]
    assert s["positive"]["hit"] == s["positive"]["n"] >= 20
    assert s["decoys"]["ok"] == s["decoys"]["n"] >= 10
    assert s["role_ok"]["false"] == 0 and s["size_ok"]["false"] == 0


def test_silent_scanner_misses_everything_and_raises_no_alarm():
    s = run(Silent())["summary"]
    assert s["positive"]["miss"] == s["positive"]["n"] and s["decoys"]["false_alarm"] == 0


def test_decoys_catch_a_naive_scanner():
    out = {r["id"]: r["outcome"] for r in run(NaiveToken())["rows"]}
    assert all(out[f"SL-{i:04d}"] == "false_alarm" for i in range(21, 31))


def test_result_is_repeatable():
    a, b = run(Oracle()), run(Oracle())
    assert a["fingerprint"] == b["fingerprint"]
    assert a["catalogue"]["sha256"] == b["catalogue"]["sha256"]
    for k in ("catalogue", "generator", "scanner", "by_form_kind", "by_family", "by_language_or_product"):
        assert k in a
    assert "SL-0001" in markdown(a)


def test_fingerprint_changes_with_outcome_or_versions():
    rows = [{"id": "SL-0001", "outcome": "hit", "role_ok": None, "size_ok": True}]
    base = fingerprint("c", "g", "s", rows)
    assert fingerprint("c", "g", "s2", rows) != base
    assert fingerprint("c2", "g", "s", rows) != base
    assert fingerprint("c", "g", "s", [dict(rows[0], outcome="miss")]) != base


def _pos(row_id):
    r = ROWS[row_id]
    return r, r["context_filename"], literal_line(r)


def test_hit_on_another_line_is_a_miss():
    r, f, ln = _pos("SL-0002")
    assert score_row(r, [Record(f, ln - 1, "ECDSA")], FAMILIES)["outcome"] == "miss"


def test_parent_family_only():
    r, f, ln = _pos("SL-0005")
    assert score_row(r, [Record(f, ln, "EC")], FAMILIES)["outcome"] == "parent_only"


def test_wrong_family():
    r, f, ln = _pos("SL-0005")
    assert score_row(r, [Record(f, ln, "RSA")], FAMILIES)["outcome"] == "wrong_family"


def test_not_use_on_positive_is_a_miss():
    r, f, ln = _pos("SL-0001")
    assert score_row(r, [Record(f, ln, "RSA", is_use=False)], FAMILIES)["outcome"] == "miss"


def test_role_and_size_scored_separately():
    r, f, ln = _pos("SL-0019")  # expected role both
    s = score_row(r, [Record(f, ln, "RSA", role="key_establishment")], FAMILIES)
    assert s["outcome"] == "hit" and s["role_ok"] is False
    r, f, ln = _pos("SL-0001")  # expected size 2048
    assert score_row(r, [Record(f, ln, "RSA", size=1024)], FAMILIES)["size_ok"] is False


def test_intrinsic_role_fills_a_missing_role():
    r, f, ln = _pos("SL-0009")  # ECDSA, expected signature
    assert score_row(r, [Record(f, ln, "ECDSA")], FAMILIES)["role_ok"] is True


def test_decoy_false_alarm_anywhere_in_tree():
    r = ROWS["SL-0023"]
    assert score_row(r, [Record(r["context_filename"], 1, "RSA")], FAMILIES)["outcome"] == "false_alarm"
    assert score_row(r, [Record(r["context_filename"], 2, "RSA", is_use=False)], FAMILIES)["outcome"] == "ok"
    assert score_row(r, [Record(r["context_filename"], 2, "AES")], FAMILIES)["outcome"] == "ok"


def test_qrp_adapter_parses_its_output():
    out = {"evidence": {
        "source_code": [
            {"path": "a.py", "line": 2, "algorithm": "ML-KEM", "evidence_kind": "declaration"},
            {"path": "a.py", "line": 1, "algorithm": "RSA", "evidence_kind": "comment", "role": "undetermined"},
            {"path": "a.py", "line": 3, "algorithm": "Ed25519", "evidence_kind": "call"},
        ],
        "protocols": [{"path": "sshd_config", "line": 1, "algorithm": None}],
        "ssh_kex": [{"path": "sshd_config", "line": 1, "algorithm": "ECDH", "key_size": 256}],
    }}
    recs = QrpMcpAdapter.parse(out)
    assert len(recs) == 4
    by = {(r.path, r.line, r.family): r for r in recs}
    assert by[("a.py", 2, "ML-KEM")].is_use is True
    assert by[("a.py", 1, "RSA")].is_use is False
    assert ("a.py", 3, "EdDSA") in by
    assert by[("sshd_config", 1, "ECDH")].role == "key_establishment"
