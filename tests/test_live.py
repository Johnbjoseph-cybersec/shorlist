"""The network axis without docker: wire.yaml against the catalogue, the scanner parsers on real
outputs captured from the planted servers (tests/fixtures/live/), the reference-client parsers, and
the scoring rules."""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "generator"))

from shorlist.catalogue import load  # noqa: E402
from shorlist.live import probe, scoring, wire as wiremod  # noqa: E402
from shorlist.live.scanners import SCANNERS, Nmap, SSLyze, SshAudit, Zeek, group, hexcode  # noqa: E402
from shorlist.live.scanners import TestSSL as _testssl  # noqa: E402  (aliased: not a pytest class)

FX = ROOT / "tests" / "fixtures" / "live"
WIRE = wiremod.load()
FORMS = {r["id"]: r for r in load(ROOT, include_withdrawn=True)}


def scored_rows():
    return {k: v for k, v in WIRE["rows"].items() if "not_runnable" not in v and "not_scored" not in v}


# ---------------- wire.yaml ----------------

def test_wire_has_no_problems():
    assert wiremod.problems(WIRE, FORMS) == []


def test_wire_ids_are_catalogue_rows_and_products_match():
    for rid, e in WIRE["rows"].items():
        assert FORMS[rid]["language_or_product"] == e["product"]
        assert FORMS[rid]["literal"].strip() == e["literal"]


def test_removal_and_ban_decoys_are_not_seen():
    """Every decoy that changes the wire (`-` removal list, `!` ban) expects its items not_seen."""
    for rid, e in scored_rows().items():
        lit = e["literal"]
        if FORMS[rid]["negative"]:
            assert e["items"] and all(i["expect"] == "not_seen" for i in e["items"]), rid
            assert "-" in lit or "!" in lit, rid
    assert {"SL-0029", "SL-0030", "SL-1190", "SL-4593", "SL-4594", "SL-4595", "SL-6527",
            "SL-0022", "SL-4577", "SL-4578", "SL-4579", "SL-2080"} <= set(scored_rows())


def test_comment_decoys_are_not_scored():
    for rid, e in WIRE["rows"].items():
        if FORMS[rid].get("decoy_class") == "comment" and "not_runnable" not in e:
            assert e.get("not_scored") == "comment_decoy", rid


def test_known_code_points():
    items = {(rid, i["name"]): i for rid, e in WIRE["rows"].items() for i in e.get("items", [])}
    assert items[("SL-0011", "X25519MLKEM768")]["code"] == "0x11EC"
    assert items[("SL-1171", "SecP384r1MLKEM1024")]["code"] == "0x11ED"
    assert items[("SL-6501", "secp256r1")]["code"] == "0x0017"
    assert items[("SL-0012", "TLS_RSA_WITH_AES_128_GCM_SHA256")]["code"] == "0x009C"
    assert items[("SL-2064", "rsa_pkcs1_sha256")]["code"] == "0x0401"
    assert items[("SL-1168", "ml-kem-768")]["code"] == "36"


def test_every_item_cites_a_source_with_date():
    for s in WIRE["sources"].values():
        assert s["url"].startswith("https://") and s["date_read"]
    for e in WIRE["rows"].values():
        for i in e.get("items", []):
            assert i["quote"]


def test_not_runnable_reasons():
    nr = {e["not_runnable"] for e in WIRE["rows"].values() if "not_runnable" in e}
    assert {"cloud", "appliance"} <= nr <= wiremod.NOT_RUNNABLE
    for rid, e in WIRE["rows"].items():
        p = e["product"]
        if p.startswith(("AWS CloudFormation", "cert-manager")) or (p.startswith("Terraform") and rid in WIRE["rows"]):
            assert e.get("not_runnable") == "cloud", rid
        if p.startswith(("Fortinet", "Juniper")):
            assert e.get("not_runnable") == "appliance", rid


def test_stats_add_up():
    s = wiremod.stats(WIRE)
    assert sum(s["by_status"].values()) == s["rows"] == len(WIRE["rows"])
    assert s["scored_positive"] + s["scored_decoy"] == s["by_status"].get("scored", 0)


# ---------------- scanner parsers on real outputs ----------------

def test_ssh_audit_parse():
    obs = SshAudit.parse(SCANNERS["ssh-audit"], "ssh", (FX / "ssh-audit_SL-0015.json").read_text(), FX)
    assert ("kex", "mlkem768x25519-sha256") in obs
    assert ("hostkey", "ssh-ed25519") in obs and ("hostkey", "rsa-sha2-512") in obs
    assert ("cipher", "chacha20-poly1305@openssh.com") in obs and any(k == "mac" for k, _ in obs)
    assert not any(k == "kex" and v == "curve25519-sha256" for k, v in obs)  # the row restricts kex to one


def test_nmap_ssh_parse():
    obs = Nmap.parse_xml((FX / "nmap-ssh_SL-0015.xml").read_text())
    assert ("kex", "mlkem768x25519-sha256") in obs and ("hostkey", "ssh-ed25519") in obs


def test_nmap_tls_parse_sees_the_hybrid_group_and_skips_tls13_suite_names():
    obs = Nmap.parse_xml((FX / "nmap-tls_SL-0011.xml").read_text())
    assert ("group", "X25519MLKEM768") in obs
    assert ("cipher_suite", "TLS_RSA_WITH_AES_128_GCM_SHA256") in obs
    assert not any(v.startswith("TLS_AKE_") for _, v in obs)
    assert not any(k == "group" and v.startswith("rsa") for k, v in obs)


def test_testssl_parse():
    obs = _testssl.parse_json(json.loads((FX / "testssl_SL-0011.json").read_text()))
    assert ("group", "X25519MLKEM768") in obs
    assert ("cipher_suite", "0x009C") in obs and ("cipher_suite", "TLS_RSA_WITH_AES_128_GCM_SHA256") in obs
    assert ("cipher_suite", "0x1301") in obs
    none = _testssl.parse_json([{"id": "FS_KEMs", "finding": "No KEMs offered"},
                                {"id": "FS_TLS12_sig_algs", "finding": "RSA+SHA256"}])
    assert none == {("sigalg", "rsa_pkcs1_sha256")}


def test_sslyze_parse_has_no_hybrid_group():
    """sslyze 6.3.1 reports the TLS 1.2 RSA suites of SL-0011 but no group: its TLS 1.3 handshakes fail
    against a server that offers only X25519MLKEM768 (captured output, not a parser limitation)."""
    d = json.loads((FX / "sslyze_SL-0011.json").read_text())
    obs = SSLyze.parse_json(d)
    assert ("cipher_suite", "TLS_RSA_WITH_AES_128_GCM_SHA256") in obs
    assert not any(k == "group" for k, _ in obs)
    assert d["sslyze_version"] == "6.3.1"


def test_zeek_parse_negotiated_values():
    obs = Zeek.parse_logs("", (FX / "zeek-ssh_SL-0015.log").read_text())
    assert ("kex", "mlkem768x25519-sha256") in obs and ("hostkey", "ssh-ed25519") in obs
    tls = Zeek.parse_logs('{"cipher":"TLS_AES_256_GCM_SHA384","curve":"X25519MLKEM768"}\n#close\n', "")
    assert tls == {("cipher_suite", "TLS_AES_256_GCM_SHA384"), ("group", "X25519MLKEM768")}


def test_name_normalisation():
    assert group("prime256v1") == "secp256r1" and group("X25519") == "x25519" and group("ecdh_x25519") == "x25519"
    assert hexcode("x9c") == "0x009C" and hexcode("xc02f") == "0xC02F"


def test_every_adapter_has_positive_controls_for_its_protocols():
    for a in SCANNERS.values():
        assert set(a.controls) == set(a.protocols), a.name
        for catch, decoy in a.controls.values():
            assert catch in scored_rows() and decoy in scored_rows(), a.name
            assert not FORMS[catch]["negative"] and FORMS[decoy]["negative"], a.name


def test_more_real_outputs():
    """One more captured output per adapter, from the full run of 2026-11-07."""
    obs = SSLyze.parse_json(json.loads((FX / "sslyze_SL-6503.json").read_text()))
    assert ("group", "x25519") in obs                                 # sslyze's catch control
    obs = Zeek.parse_logs((FX / "zeek-ssl_SL-0012.log").read_text(), "")
    assert ("cipher_suite", "TLS_RSA_WITH_AES_128_GCM_SHA256") in obs  # Zeek's TLS catch control
    obs = Nmap.parse_xml((FX / "nmap-tls_SL-0022.xml").read_text())
    assert obs and not any(k == "cipher_suite" and v.startswith("TLS_RSA_WITH_") for k, v in obs)  # !kRSA
    obs = SshAudit.parse(SCANNERS["ssh-audit"], "ssh", (FX / "ssh-audit_SL-4595.json").read_text(), FX)
    assert ("kex", "diffie-hellman-group1-sha1") not in obs and ("kex", "mlkem768x25519-sha256") in obs
    obs = _testssl.parse_json(json.loads((FX / "testssl_SL-2063.json").read_text()))
    assert ("sigalg", "ecdsa_secp256r1_sha256") in obs                # testssl reports signature schemes
    row = WIRE["rows"]["SL-2063"]
    assert scoring.score(row, {"status": "started", "reference": []}, obs)["outcome"] == "hit"


# ---------------- reference client ----------------

def test_reference_output_fixture():
    ref = json.loads((FX / "reference_SL-0015.json").read_text().strip().splitlines()[-1])
    assert ref["server_lists"]["kex"][0] == "mlkem768x25519-sha256"
    assert ref["items"][0]["on_wire"] is True


def test_parse_ssh_vv():
    vv = "\n".join([
        "debug2: KEX algorithms: curve25519-sha256,ext-info-c",
        "debug2: peer server KEXINIT proposal",
        "debug2: KEX algorithms: mlkem768x25519-sha256,ext-info-s",
        "debug2: host key algorithms: ssh-ed25519",
        "debug2: ciphers ctos: aes128-ctr", "debug2: ciphers stoc: aes256-ctr",
        "debug2: MACs ctos: hmac-sha1", "debug2: MACs stoc: hmac-sha1",
        "debug1: kex_ext_info_client_parse: server-sig-algs=<ecdsa-sha2-nistp256,ssh-ed25519>"])
    lists = probe.parse_ssh_vv(vv)
    assert lists["kex"] == ["mlkem768x25519-sha256", "ext-info-s"]
    assert lists["cipher"] == ["aes128-ctr", "aes256-ctr"] and lists["mac"] == ["hmac-sha1"]
    assert lists["server_sig_alg"] == ["ecdsa-sha2-nistp256", "ssh-ed25519"]


def test_s_client_parsers():
    assert probe.s_client_group("Negotiated TLS1.3 group: X25519MLKEM768\n") == "X25519MLKEM768"
    assert probe.s_client_group("Peer Temp Key: ECDH, secp384r1, 384 bits\n") == "secp384r1"
    assert probe.s_client_group("Peer Temp Key: X25519, 253 bits\n") == "x25519"
    assert probe.s_client_group("New, (NONE), Cipher is (NONE)\n") is None
    assert probe.s_client_sigalg("Peer signature type: ecdsa_secp256r1_sha256\n") == "ecdsa_secp256r1_sha256"


def test_raw_client_hello_offers_exactly_the_codes():
    h = probe.client_hello([0x0005, 0x000A], "srv")
    assert h[0] == 0x16 and h[5] == 0x01
    off = 5 + 4 + 2 + 32 + 1
    n = struct.unpack("!H", h[off:off + 2])[0]
    assert h[off + 2:off + 2 + n] == b"\x00\x05\x00\x0a"
    sh = b"\x16\x03\x03\x00\x30\x02\x00\x00\x2c\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x9c" + b"\x00"
    assert probe.parse_server_answer(sh) == {"answer": "server_hello", "version": "0x0303", "cipher": "0x009C"}
    assert probe.parse_server_answer(b"\x15\x03\x03\x00\x02\x02\x28") == {"answer": "alert", "alert": 40}


# ---------------- scoring ----------------

ROW_POS = {"protocol": "tls", "items": [{"kind": "group", "name": "secp256r1", "code": "0x0017", "aliases": ["prime256v1"], "expect": "seen"}]}
ROW_NEG = {"protocol": "ssh", "items": [{"kind": "kex", "name": "mlkem768x25519-sha256", "expect": "not_seen"}]}
STARTED = {"status": "started", "reference": [{"name": "x", "expect": "seen", "on_wire": True}]}


def test_score_outcomes():
    assert scoring.score(ROW_POS, STARTED, {("group", "prime256v1")})["outcome"] == "hit"
    assert scoring.score(ROW_POS, STARTED, {("group", "0x0017")})["outcome"] == "hit"
    assert scoring.score(ROW_POS, STARTED, {("group", "x25519")})["outcome"] == "miss"
    assert scoring.score(ROW_POS, STARTED, {("cipher_suite", "secp256r1")})["outcome"] == "miss"
    ref_neg = {"status": "started", "reference": [{"name": "m", "expect": "not_seen", "on_wire": False}]}
    assert scoring.score(ROW_NEG, ref_neg, {("kex", "curve25519-sha256")})["outcome"] == "ok"
    assert scoring.score(ROW_NEG, ref_neg, {("kex", "mlkem768x25519-sha256")})["outcome"] == "false_alarm"


def test_score_gates_before_the_scanner():
    assert scoring.score({**ROW_POS, "not_runnable": "cloud"}, {}, None) == {"outcome": "not_runnable", "reason": "cloud"}
    assert scoring.score(ROW_POS, {"status": "config_rejected", "error": "e"}, None)["reason"] == "config_rejected"
    off = {"status": "started", "reference": [{"name": "x", "expect": "seen", "on_wire": False}]}
    assert scoring.score(ROW_POS, off, {("group", "secp256r1")})["reason"] == "not_offered"
    contra = {"status": "started", "reference": [{"name": "m", "expect": "not_seen", "on_wire": True}]}
    assert scoring.score(ROW_NEG, contra, set())["reason"] == "expectation_contradicted"
    assert scoring.score(ROW_POS, {**STARTED, "scanner_error": "timeout"}, None)["outcome"] == "scanner_error"


def test_fingerprint_depends_on_outcomes_only_through_rows():
    rows = [{"id": "SL-0011", "outcome": "hit"}]
    a = scoring.fingerprint("w", "c", "g", "s", {"x": "y"}, rows)
    assert a == scoring.fingerprint("w", "c", "g", "s", {"x": "y"}, [dict(r) for r in rows])
    assert a != scoring.fingerprint("w", "c", "g", "s", {"x": "y"}, [{"id": "SL-0011", "outcome": "miss"}])
    assert a != scoring.fingerprint("w2", "c", "g", "s", {"x": "y"}, rows)


def test_cli_registers_live():
    from shorlist.__main__ import main
    assert main(["live", "--stats"]) == 0


def test_reference_fixtures_gate_scoring():
    """SL-0014: server-sig-algs is on the wire (reference reads it after key exchange).
    SL-4570: NULL-MD5 is configured but the server answers a hello offering only it with alert 40."""
    r14 = json.loads((FX / "reference_SL-0014.json").read_text().strip().splitlines()[-1])
    assert r14["items"][0]["kind"] == "server_sig_alg" and r14["items"][0]["on_wire"] is True
    r70 = json.loads((FX / "reference_SL-4570.json").read_text().strip().splitlines()[-1])
    assert r70["items"][0]["on_wire"] is False and "'alert': 40" in r70["items"][0]["evidence"]
    s = scoring.score(WIRE["rows"]["SL-4570"], {"status": "started", "reference": r70["items"]}, set())
    assert s == {"outcome": "not_scored", "reason": "not_offered"}
