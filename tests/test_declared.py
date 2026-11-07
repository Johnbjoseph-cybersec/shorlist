"""Declaration axis (PLAN.md section 12). No docker: the observations are the captured files in
generator/shorlist/declared/observations/, the tool outputs are captured stdout in
tests/fixtures/declared/<tool>/<row>.stdout.txt (sbom-tools 0.3.0 and cyclonedx-cli 0.33.1, 2026-11-07)."""
import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "generator"))

from shorlist.__main__ import main  # noqa: E402
from shorlist.declared import adapters, observed, probe, reference, registry, rows, scoring  # noqa: E402
from shorlist.declared.run import run  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "declared"
RESULTS = ROOT / "results" / "declared"
ROWS = {r["id"]: r for r in rows.load()}


def obs_of(rid):
    return rows.observation(ROWS[rid]["listener"])


# ---------------------------------------------------------------- rows, listeners, observations
def test_rows_validate():
    assert rows.problems() == []


def test_row_counts():
    st = rows.stats()
    assert 30 <= st["rows"] - st["not_scored"] <= 60
    assert set(st["by_verdict"]) == set(rows.VERDICTS)
    assert set(st["by_server"]) == {"nginx", "apache", "s_server"}
    assert set(st["by_decoy"]) - {"-"} == set(rows.DECOYS)
    assert st["not_scored"] == 2


def test_ssh_rows_not_scored_with_reason():
    ssh = [r for r in ROWS.values() if r["compare"]["protocol"] == "ssh"]
    assert len(ssh) == 2 and all(r["not_scored"] == "no_spec_structure" and "1162" in r["reason"] for r in ssh)


def test_every_observation_is_captured_and_current():
    for lid, lst in rows.listeners().items():
        o = rows.observation(lid)
        assert o["observation_status"] == "captured" and o["method"] == "accepted"
        assert o["config_sha256"] == rows.servers.config_sha256(lst)
        assert len(o["evidence"]["groups"]) == len(registry.CANDIDATE_GROUPS)


@pytest.mark.parametrize("mutate,expect", [
    (lambda r: r["declaration"]["components"][1]["cryptoProperties"]["algorithmProperties"].__setitem__("ellipticCurve", "Curve25519"),
     "declaration schema"),
    (lambda r: r.__setitem__("verdict", "undeclared"), "reference says"),
    (lambda r: r["resolves_to"][0].__setitem__("quote", r["resolves_to"][0]["quote"][:-1]), "not verbatim"),
    (lambda r: r.__setitem__("listener", "L-SSV-1"), "reference says"),
])
def test_validator_negative_controls(mutate, expect):
    r = copy.deepcopy(ROWS["SLD-0001"])
    mutate(r)
    errs = rows.problems([r])
    assert errs and any(expect in e for e in errs), errs


def test_focus_quote_is_checked():
    r = copy.deepcopy(ROWS["SLD-0003"])
    r["focus"]["quote"] = r["focus"]["quote"].replace("Y,Y", "Y,N")
    assert any("not verbatim" in e for e in rows.problems([r]))


def test_excluded_scope_is_what_keeps_a_row_consistent():
    r = copy.deepcopy(ROWS["SLD-0011"])  # static-RSA suite in a scope: excluded component
    next(c for c in r["declaration"]["components"] if c.get("scope"))["scope"] = "required"
    assert reference.compare(r["declaration"], obs_of("SLD-0011"), "cipher_suite")["verdict"] == "overclaimed"


# ---------------------------------------------------------------- registry and the reference comparator
def test_spellings_resolve_to_iana_code_points():
    assert registry.suite_code(["0x13", "0x01"], None) == registry.suite_code(["0x13,0x01"], None) == "0x1301"
    assert registry.suite_code(None, "ECDHE-RSA-AES256-GCM-SHA384") == "0xC030"
    assert registry.group_code("0x11EC") == registry.group_code("X25519MLKEM768") == "0x11EC"
    assert registry.group_code("X25519") == "0x001D"
    c = registry.curves()
    assert c["nist/p-256"] == c["secg/secp256r1"] == c["x962/prime256v1"] == "secp256r1"
    assert c["other/curve25519"] == "x25519"
    assert registry.hybrid_parts("0x11EC") == frozenset({"x25519", "ML-KEM-768"})
    assert registry.hybrid_parts("0x0201") is None


def test_parameter_mismatch_needs_one_item_each_side_in_one_family():
    o = {"accepted": {"group": [{"code": "0x0017"}]}, "candidates": {"group": ["0x0017", "0x0018", "0x001D"]}}
    decl = lambda gs: {"components": [{"type": "cryptographic-asset", "bom-ref": "p", "cryptoProperties": {  # noqa: E731
        "assetType": "protocol", "protocolProperties": {"type": "tls", "cipherSuites": [{"tlsGroups": gs}]}}}]}
    assert reference.compare(decl(["secp384r1"]), o, "group")["verdict"] == "parameter_mismatch"
    assert reference.compare(decl(["secp384r1", "x25519"]), o, "group")["verdict"] == "undecidable"
    assert reference.compare(decl(["secp256r1", "x25519"]), o, "group")["verdict"] == "overclaimed"
    assert reference.compare(decl(["ffdhe9999"]), o, "group")["verdict"] == "undecidable"  # unresolvable spelling


def test_reference_positive_control_scores_100_percent():
    res = run("reference", log=lambda m: None)
    s = res["summary"]
    assert res["control_passed"] is True
    assert s["non_consistent"]["hit"] == s["non_consistent"]["n"] and s["consistent"]["ok"] == s["consistent"]["n"]


# ---------------------------------------------------------------- observed CBOM
def test_observed_cbom_is_valid_and_neutral():
    for lid in rows.listeners():
        o = rows.observation(lid)
        b = observed.build(o)
        assert rows.schema_errors(b) == []
        assert {c["name"] for c in b["components"]} <= {"TLSv1.3", "TLSv1.2"}
        for c in b["components"]:
            assert c["cryptoProperties"]["assetType"] == "protocol"
            for cs in c["cryptoProperties"]["protocolProperties"]["cipherSuites"]:
                if "identifiers" in cs:
                    assert len(cs["identifiers"]) == 1 and "," in cs["identifiers"][0]


# ---------------------------------------------------------------- adapters on captured outputs
def recorded(tool):
    return {s["id"]: s for s in json.loads((RESULTS / f"{tool}.json").read_text())["rows_scored"]}


@pytest.mark.parametrize("tool", ["sbom-tools", "cyclonedx-cli"])
def test_adapter_parses_captured_outputs_like_the_recorded_run(tool):
    t = adapters.TOOLS[tool]()
    rec = recorded(tool)
    files = sorted((FIX / tool).glob("*.stdout.txt"))
    assert len(files) >= 6
    for f in files:
        rid = f.name.split(".")[0]
        r = ROWS[rid]
        out = t.parse(f.read_text(), r["declaration"], observed.build(obs_of(rid)))
        s = scoring.score(r, out)
        assert s["outcome"] == rec[rid]["outcome"], (rid, s, rec[rid])


def test_sbom_tools_combiner_decoy_is_a_false_alarm_from_removed_algorithm_components():
    r = ROWS["SLD-0001"]
    out = adapters.SbomTools().parse((FIX / "sbom-tools" / "SLD-0001.stdout.txt").read_text(), r["declaration"],
                                     observed.build(obs_of("SLD-0001")))
    refs = {f["element"]["ref"] for f in out["findings"] if f["category"] == "group"}
    assert refs == {"alg/mlkem768", "alg/x25519", "alg/hybrid"}


def test_tools_say_nothing_about_tlsgroups_inside_a_paired_component():
    # SLD-0008: declared secp384r1, accepted secp256r1, both inside the paired "TLSv1.3" component
    for tool in ("sbom-tools", "cyclonedx-cli"):
        r = ROWS["SLD-0008"]
        out = adapters.TOOLS[tool]().parse((FIX / tool / "SLD-0008.stdout.txt").read_text(), r["declaration"],
                                           observed.build(obs_of("SLD-0008")))
        assert [f for f in out["findings"] if f["category"] == "group"] == []


def test_component_level_rows_are_hits_for_both_tools():
    for tool in ("sbom-tools", "cyclonedx-cli"):
        rec = recorded(tool)
        assert all(rec[i]["outcome"] == "hit" for i in ("SLD-0056", "SLD-0057", "SLD-0058"))


# ---------------------------------------------------------------- scoring
def pm_row():
    return ROWS["SLD-0008"]


def test_partial_is_its_own_column():
    r = pm_row()
    f = [{"verdict": "undeclared", "category": "group", "element": {"value": "secp256r1"}, "tool_says": "x"},
         {"verdict": "overclaimed", "category": "group", "element": {"value": "secp384r1"}, "tool_says": "y"}]
    assert scoring.score(r, {"findings": f})["outcome"] == "partial"
    linked = [{"verdict": "parameter_mismatch", "category": "group",
               "element": {"declared": "secp384r1", "observed": "0x0017"}, "tool_says": "z"}]
    assert scoring.score(r, {"findings": linked})["outcome"] == "hit"


def test_extra_findings_and_other_categories():
    r = ROWS["SLD-0003"]  # overclaimed secp256r1
    one = {"verdict": "overclaimed", "category": "group", "element": {"value": "secp256r1"}, "tool_says": "a"}
    other = {"verdict": "overclaimed", "category": "cipher_suite", "element": {"name": "TLS_AES_128_GCM_SHA256"}, "tool_says": "b"}
    extra = {"verdict": "undeclared", "category": "group", "element": {"value": "x25519"}, "tool_says": "c"}
    assert scoring.score(r, {"findings": [one, other]})["outcome"] == "hit"
    assert scoring.score(r, {"findings": [one, extra]})["outcome"] == "miss"
    assert scoring.score(r, {"findings": []})["outcome"] == "miss"
    assert scoring.score(ROWS["SLD-0002"], {"findings": [extra]})["outcome"] == "false_alarm"


@pytest.mark.parametrize("tool", ["reference", "sbom-tools", "cyclonedx-cli"])
def test_recorded_fingerprint_reproduces(tool):
    res = json.loads((RESULTS / f"{tool}.json").read_text())
    assert res["rows"]["sha256"] == rows.rows_sha256()
    assert scoring.fingerprint(res["rows"]["sha256"], res["generator"]["version"], res["tool"]["version"],
                               res["rows_scored"]) == res["fingerprint"]


# ---------------------------------------------------------------- probe parsing and CLI
def test_probe_parses_s_client_output():
    assert probe.negotiated_group("Negotiated TLS1.3 group: X25519MLKEM768\n") == "X25519MLKEM768"
    assert probe.negotiated_group("Negotiated TLS1.3 group: <NULL>\nPeer Temp Key: DH, 2048 bits\n") == "ffdhe2048"
    assert probe.negotiated_group("Server Temp Key: ECDH, prime256v1, 256 bits\n") == "secp256r1"
    assert probe.negotiated_group("Negotiated TLS1.3 group: <NULL>\n") is None
    assert probe.negotiated_cipher("New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n") == ("TLSv1.3", "TLS_AES_256_GCM_SHA384")
    sh = bytes.fromhex("160303004a0200004603030000") + b"\x00" * 30 + b"\x00" + bytes.fromhex("c02f00")
    assert probe.parse_server_answer(sh)["cipher"] == "0xC02F"
    assert probe.parse_server_answer(bytes.fromhex("15030300020228"))["answer"] == "alert"


def test_cli_validate_and_table(capsys):
    assert main(["declared", "--validate"]) == 0
    assert main(["declared", "--table", str(RESULTS / "sbom-tools.json")]) == 0
    assert "By verdict class" in capsys.readouterr().out
