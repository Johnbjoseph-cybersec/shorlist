"""The three scoring axes (v0.2): quantum, weak, defect. Synthetic rows, so these tests do
not depend on which wave-4/5 rows exist in forms/."""
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "generator"))

from shorlist.adapters.base import Record  # noqa: E402
from shorlist.catalogue import load, load_families, load_schema, row_axis, validate_row  # noqa: E402
from shorlist.run import _axes  # noqa: E402
from shorlist.score import score_fix, score_row  # noqa: E402

SCHEMA, FAMILIES = load_schema(), load_families()
ROWS = {r["id"]: r for r in load()}

BASE = {
    "id": "SL-9000", "title": "synthetic row", "parameter_set": None, "form_kind": "api_call",
    "language_or_product": "Python / hashlib", "context_filename": "h.py", "negative": False,
    "source": [{"url": "https://example.org/spec", "section": "Section 1", "read_at": "2026-11-06", "quote": "q"}],
    "status": "verified-source", "added_by": "test", "added_at": "2026-11-06",
}
WEAK = {"status": "disallowed", "anchor": "NIST SP 800-131A Rev. 2, Table 8", "quote": "SHA-1 ... Disallowed"}


def md5_row():
    return BASE | {"family": "MD5", "role": "hash", "literal": "hashlib.md5(data)",
                   "context_template": "import hashlib\nd = hashlib.md5(data)\n",
                   "expected": {"family": "MD5", "role": "hash", "size": "undetermined"},
                   "weakness": copy.deepcopy(WEAK)}


def ecb_row():
    return BASE | {"id": "SL-9001", "family": "AES", "role": "encryption", "row_kind": "defect",
                   "literal": "c = AES.new(key, AES.MODE_ECB)",
                   "context_template": "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_ECB)\n",
                   "right_template": "from Crypto.Cipher import AES\nc = AES.new(key, AES.MODE_GCM)\n",
                   "expected": {"family": "AES", "role": "encryption", "size": "undetermined"},
                   "defect": {"cwe": "CWE-327", "taxonomy": ["CryptoAPI-Bench: ECB mode"]}}


def test_every_family_has_an_axis_and_existing_rows_are_quantum():
    assert {f["axis"] for f in FAMILIES.values()} == {"quantum", "weak", "defect"}
    assert {row_axis(r, FAMILIES) for r in ROWS.values() if int(r["id"][3:]) < 4000} == {"quantum"}


def test_synthetic_rows_validate():
    assert validate_row(md5_row(), None, SCHEMA, FAMILIES) == []
    assert validate_row(ecb_row(), None, SCHEMA, FAMILIES) == []
    assert row_axis(md5_row(), FAMILIES) == "weak" and row_axis(ecb_row(), FAMILIES) == "defect"


def test_weak_family_needs_weakness_and_defect_family_needs_defect_row():
    r = md5_row(); del r["weakness"]
    assert any("needs `weakness`" in e for e in validate_row(r, None, SCHEMA, FAMILIES))
    r = ecb_row(); del r["row_kind"]; del r["defect"]; del r["right_template"]
    assert any("only in a row with row_kind: defect" in e for e in validate_row(r, None, SCHEMA, FAMILIES))


def test_defect_row_needs_cwe_and_a_right_template_without_the_literal():
    r = ecb_row(); del r["right_template"]
    assert validate_row(r, None, SCHEMA, FAMILIES)  # schema: right_template required
    r = ecb_row(); r["right_template"] = r["context_template"]
    assert any("right_template still contains" in e for e in validate_row(r, None, SCHEMA, FAMILIES))
    r = ecb_row(); r["defect"]["cwe"] = "327"
    assert validate_row(r, None, SCHEMA, FAMILIES)
    r = md5_row(); r["right_template"] = "x = 1\n"
    assert validate_row(r, None, SCHEMA, FAMILIES)  # right_template only on defect rows


def test_quantum_axis_ignores_weak_and_defect_families():
    r = ROWS["SL-0023"]  # a quantum decoy
    for fam in ("MD5", "AES", "SHA-1", "RNG"):
        assert score_row(r, [Record(r["context_filename"], 1, fam)], FAMILIES)["outcome"] == "ok"


def test_weak_axis_scores_the_family_and_sees_quantum_families():
    r = md5_row()
    assert score_row(r, [Record("h.py", 2, "MD5")], FAMILIES)["outcome"] == "hit"
    assert score_row(r, [Record("h.py", 2, "RSA")], FAMILIES)["outcome"] == "wrong_family"
    assert score_row(r, [Record("h.py", 2, "AES")], FAMILIES)["outcome"] == "miss"
    rsa1024 = copy.deepcopy(ROWS["SL-0001"]) | {"weakness": copy.deepcopy(WEAK)}
    assert row_axis(rsa1024, FAMILIES) == "weak"


def test_defect_axis_scores_the_cwe_and_the_fixed_file():
    r = ecb_row()
    hit = score_row(r, [Record("h.py", 2, "AES", cwe="CWE-327")], FAMILIES)
    assert hit["outcome"] == "hit" and hit["axis"] == "defect"
    assert score_row(r, [Record("h.py", 2, "AES", cwe="CWE-329")], FAMILIES)["outcome"] == "wrong_class"
    assert score_row(r, [Record("h.py", 2, "AES")], FAMILIES)["outcome"] == "miss"  # family alone is not the defect
    assert score_row(r, [Record("h.py", 1, "AES", cwe="CWE-327")], FAMILIES)["outcome"] == "miss"
    assert score_fix(r, [Record("h.py", 2, "AES", cwe="CWE-327")])["outcome"] == "false_alarm"
    assert score_fix(r, [Record("h.py", 2, "AES")])["outcome"] == "ok"


def test_axes_summary_keeps_axes_apart():
    scored = [
        {"id": "a", "axis": "quantum", "negative": False, "outcome": "hit", "size_ok": None},
        {"id": "b", "axis": "weak", "negative": False, "outcome": "hit", "size_ok": True},
        {"id": "c", "axis": "defect", "negative": False, "outcome": "miss", "fix": {"outcome": "false_alarm"}},
    ]
    a = _axes(scored)
    assert a["weak"]["positive"]["hit"] == 1 and a["weak"]["positive"]["n"] == 1
    assert a["defect"]["positive"]["miss"] == 1 and a["defect"]["fixed_files"]["false_alarm"] == 1
    assert _axes(scored[:1]) == {}


def test_defect_decoy_has_no_right_template():
    r = ecb_row() | {"negative": True, "decoy_class": "comment",
                     "literal": "# never use AES.MODE_ECB", "context_template": "# never use AES.MODE_ECB\n"}
    del r["right_template"]
    assert validate_row(r, None, SCHEMA, FAMILIES) == []
    r["right_template"] = "x = 1\n"
    assert validate_row(r, None, SCHEMA, FAMILIES)


def test_run_end_to_end_with_a_defect_row(tmp_path):
    import shutil
    import yaml
    from shorlist.adapters.base import Adapter
    from shorlist.run import markdown, run

    shutil.copytree(ROOT / "schema", tmp_path / "schema")
    shutil.copy(ROOT / "VERSION", tmp_path / "VERSION")
    (tmp_path / "forms").mkdir()
    shutil.copy(ROOT / "forms" / "SL-0001.yaml", tmp_path / "forms" / "SL-0001.yaml")
    row = ecb_row()
    (tmp_path / "forms" / f"{row['id']}.yaml").write_text(yaml.safe_dump(row, sort_keys=False))

    class FlagsEcb(Adapter):
        """Reports CWE-327 on any line with MODE_ECB, and nothing else."""
        name = "flags-ecb"

        def version(self):
            return "flags-ecb 1"

        def scan(self, tree, workdir):
            (f,) = list(tree.iterdir())
            return [Record(f.name, n, "AES", cwe="CWE-327")
                    for n, line in enumerate(f.read_text().split("\n"), 1) if "MODE_ECB" in line]

    res = run(FlagsEcb(), tmp_path)
    assert res["catalogue"]["by_axis"] == {"quantum": 1, "weak": 0, "defect": 1}
    assert res["summary"]["positive"]["n"] == 1 and res["summary"]["positive"]["miss"] == 1  # quantum only
    d = res["axes"]["defect"]
    assert d["positive"] == {"hit": 1, "wrong_class": 0, "miss": 0, "n": 1}
    assert d["fixed_files"] == {"ok": 1, "false_alarm": 0, "n": 1}
    assert "SL-9001/fix" in res["raw_records"]
    assert "fixed file: ok" in markdown(res)


def test_scanner_error_row_is_listed_and_left_out_of_the_denominators(tmp_path):
    import shutil
    import yaml
    from shorlist.adapters.base import Adapter, ScannerTimeout
    from shorlist.run import markdown, run

    shutil.copytree(ROOT / "schema", tmp_path / "schema")
    shutil.copy(ROOT / "VERSION", tmp_path / "VERSION")
    (tmp_path / "forms").mkdir()
    for rid in ("SL-0001", "SL-0002", "SL-3605"):
        shutil.copy(ROOT / "forms" / f"{rid}.yaml", tmp_path / "forms" / f"{rid}.yaml")
    row = ecb_row()
    (tmp_path / "forms" / f"{row['id']}.yaml").write_text(yaml.safe_dump(row, sort_keys=False))
    hang = {ROWS["SL-0002"]["context_template"], row["right_template"]}

    class Hangs(Adapter):
        name = "hangs"

        def version(self):
            return "hangs 1"

        def scan(self, tree, workdir):
            (f,) = list(tree.iterdir())
            if f.read_text() in hang:
                raise ScannerTimeout(f"hangs: {tree.parent.name} timed out twice after 1 s")
            return []

    res = run(Hangs(), tmp_path)
    by = {s["id"]: s for s in res["rows"]}
    assert by["SL-0002"]["outcome"] == "scanner_error" and by["SL-0001"]["outcome"] == "miss"
    assert res["catalogue"]["positive"] == 2 and res["catalogue"]["decoys"] == 1  # the catalogue, in full
    assert res["summary"]["positive"]["n"] == 1 and res["summary"]["positive"]["miss"] == 1
    assert res["summary"]["scanner_error"] == {"n": 1, "ids": ["SL-0002"]}
    assert res["scanner_error"] == {"n": 1, "ids": ["SL-0002"]}
    assert "1 row(s) not scored" in res["summary"]["statement"]
    assert sum(c["positive"] for c in res["by_family"].values()) == 1
    d = res["axes"]["defect"]  # the defect row's fixed file timed out: left out of fixed_files
    assert by["SL-9001"]["fix"]["outcome"] == "scanner_error" and d["fixed_files"]["n"] == 0
    md = markdown(res)
    assert "| SL-0002 |  | scanner_error |" in md and "not scored (scanner_error)" in md
