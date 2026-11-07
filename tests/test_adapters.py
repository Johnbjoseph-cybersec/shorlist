"""Parsing tests for the container adapters, on the output shapes their documentation shows.
No docker needed: only parse() and the command plumbing are exercised."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "generator"))

from shorlist.adapters import ADAPTERS  # noqa: E402
from shorlist.adapters._container import ContainerAdapter, rel_path  # noqa: E402
from shorlist.adapters._cyclonedx import family  # noqa: E402
from shorlist.adapters.base import Record  # noqa: E402
from shorlist.adapters.cdxgen import CdxgenAdapter  # noqa: E402
from shorlist.adapters.cipheriq import CipherIQAdapter, CipherIQServicesAdapter  # noqa: E402
from shorlist.adapters.cryptoscan import CryptoScanAdapter  # noqa: E402
from shorlist.adapters.qscan import QscanAdapter  # noqa: E402
from shorlist.adapters.semgrep import SemgrepAdapter, family_from_check_id  # noqa: E402


def test_all_adapters_registered():
    assert {"qrp-mcp", "cryptoscan", "cbomkit-theia", "cipheriq-cbom-generator",
            "cipheriq-cbom-generator-services", "cdxgen", "qscan", "semgrep"} <= set(ADAPTERS)


def test_family_uses_only_the_families_yaml_vocabulary():
    assert family("RSA-2048") == "RSA"
    assert family("ML-KEM-768") == "ML-KEM"
    assert family("RSASSA-PKCS1-2048-SHA256") == "RSA"
    assert family("FFDH") == "DH"
    assert family("ECDH") == "ECDH"
    assert family("ECC") is None and family("SHA256withECDSA") is None and family("X25519MLKEM768") is None


def test_rel_path():
    assert rel_path("/scan/keys.py") == "keys.py"
    assert rel_path("./keys.py") == "keys.py"
    assert rel_path("keys.py") == "keys.py"
    assert rel_path("/usr/lib/libssl.so") == ""


def test_container_command_gets_mounts_and_records_no_host_path(tmp_path):
    a = CryptoScanAdapter()
    assert a.command[:2] == ["docker", "run"] and "--network" in a.command and "none" in a.command
    assert not any("/" in w and w.startswith("/") for w in a.command if w != "/tmp:rw,size=512m")
    argv = a._argv(["version"], None, ["-v", f"{tmp_path}:/scan:ro"])
    assert argv[:4] == ["docker", "run", "-v", f"{tmp_path}:/scan:ro"] and argv[-2:] == [a.command[-1], "version"]
    try:
        CryptoScanAdapter(["cryptoscan"])
        raise AssertionError("a non-docker command must be refused")
    except ValueError:
        pass
    assert isinstance(a, ContainerAdapter)


# docs/cbom-fields.md and docs/commands.md (csnp/cryptoscan v1.5.0): components[].name,
# evidence.occurrences[].location/line
CRYPTOSCAN_BOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
    {"type": "cryptographic-asset", "name": "MD5",
     "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
     "evidence": {"occurrences": [{"location": "CryptoSamples.java", "line": 96, "symbol": "MD5"}]}},
    {"type": "cryptographic-asset", "name": "RSA",
     "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "pke", "classicalSecurityLevel": 112}},
     "evidence": {"occurrences": [{"location": "keys.py", "line": 1}, {"location": "keys.py", "line": 3}]}}]}


def test_cryptoscan_parse():
    recs = CryptoScanAdapter.parse(CRYPTOSCAN_BOM)
    assert Record("CryptoSamples.java", 96, "MD5") in recs
    assert Record("keys.py", 3, "RSA", None, None) in recs  # pke -> no role; security level is not a size
    assert len(recs) == 3


# PATTERNS.md (csnp/cryptoscan v1.5.0) L139 ECC-001 "Elliptic Curve", L117 HYBRID-KEM-001
# "X25519+ML-KEM Hybrid Key Exchange", L118-119 composite signatures with ML-DSA
def test_cryptoscan_maps_its_documented_names():
    bom = {"components": [
        {"type": "cryptographic-asset", "name": n,
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": p}},
         "evidence": {"occurrences": [{"location": "a.py", "line": i}]}}
        for i, (n, p) in enumerate([("ECC", "other"), ("Hybrid-KEM", "combiner"),
                                    ("Composite-Signature", "signature"), ("Hybrid-TLS", "other")], 1)]}
    fams = [r.family for r in CryptoScanAdapter.parse(bom)]
    assert fams == ["EC", "ML-KEM", "ML-DSA", "Hybrid-TLS"]  # Hybrid-TLS: not in the pattern table


def test_cipheriq_component_without_location_gives_no_record():
    bom = {"components": [{"type": "cryptographic-asset", "name": "RSA",
                           "cryptoProperties": {"algorithmProperties": {"primitive": "signature"}}},
                          {"type": "library", "name": "libssl3t64"}]}
    assert CipherIQAdapter.parse(bom) == []
    assert CipherIQServicesAdapter.parse(bom) == []


def test_cipheriq_services_uses_the_readme_invocation():
    a = CipherIQServicesAdapter()
    assert a.ARGS == ["--discover-services", "--plugin-dir", "/usr/local/share/cbom-generator/plugins/ubuntu",
                      "--cyclonedx-spec=1.7"]
    assert a.image == CipherIQAdapter.image


# docs/ADVANCED.md (cdxgen v13.6.0), "The shape of a cryptographic-asset component"
def test_cdxgen_parse_source_location_property():
    bom = {"components": [
        {"type": "cryptographic-asset", "name": "sha-256",
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"algorithmFamily": "SHA-2", "primitive": "kdf"}},
         "properties": [{"name": "cdx:crypto:sourceLocation", "value": "src/crypto.js:12:9"}]},
        {"type": "cryptographic-asset", "name": "ml-kem-768",
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"algorithmFamily": "ML-KEM", "primitive": "kem"}},
         "properties": [{"name": "cdx:crypto:sourceLocation", "value": "/scan/kem.py:3:1"}]},
        {"type": "library", "name": "cryptography"}]}
    recs = CdxgenAdapter.parse(bom)
    # SHA-2 is in the vocabulary since v0.2 (defect_only); the quantum scorer still ignores it.
    assert Record("src/crypto.js", 12, "SHA-2") in recs
    assert Record("kem.py", 3, "ML-KEM", "key_establishment") in recs
    assert len(recs) == 2


# docs/cbom-format.md (EthanCratchley/qscan @8b737992), "Components" and "Custom Properties"
def test_qscan_parse():
    bom = {"components": [{"name": "RSA-2048", "type": "cryptographic-asset",
                           "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
                               "primitive": "pke", "cryptoFunctions": ["keygen"], "parameterSetIdentifier": "2048"}},
                           "properties": [{"name": "qscan:severity", "value": "high"},
                                          {"name": "qscan:filePath", "value": "src/crypto_utils.py"},
                                          {"name": "qscan:lineNumber", "value": "42"}]}]}
    assert QscanAdapter.parse(bom) == [Record("src/crypto_utils.py", 42, "RSA", None, 2048)]


# Semgrep CLI JSON output: results[].check_id, path, start.line
def test_semgrep_parse():
    res = {"results": [
        {"check_id": "python.cryptography.security.insufficient-rsa-key-size.insufficient-rsa-key-size",
         "path": "/scan/keys.py", "start": {"line": 3, "col": 7}, "extra": {}},
        {"check_id": "python.cryptography.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5",
         "path": "/scan/h.py", "start": {"line": 2}, "extra": {}}], "errors": []}
    recs = SemgrepAdapter.parse(res)
    assert recs[0] == Record("keys.py", 3, "RSA")
    assert recs[1].family == "MD5"  # classically_weak since v0.2; scored on the weak axis only
    assert family_from_check_id("go.lang.security.audit.crypto.use_of_weak_rsa_key.use-of-weak-rsa-key") == "RSA"


# v0.2 weak axis: each scanner's own spellings of the classically weak families, mapped only as the
# scanner's own rule table defines them (the line is cited in the adapter).

# qrp-mcp 0.44.0 src/qrp_mcp/detectors.py L450: ("SHA1", "SHA-1 usage", ...)
def test_qrp_mcp_maps_sha1_and_writes_no_cwe():
    from shorlist.adapters.qrp_mcp import QrpMcpAdapter
    res = {"evidence": {"source_code": [
        {"path": "fp.py", "line": 5, "algorithm": "SHA1", "evidence_kind": "call"},
        {"path": "fp.py", "line": 6, "algorithm": "3DES", "evidence_kind": "call"},
        {"path": "enc.py", "line": 3, "algorithm": "AES-ECB", "evidence_kind": "call"}]}}
    recs = QrpMcpAdapter.parse(res)
    assert [r.family for r in recs] == ["SHA-1", "3DES", "AES-ECB"]
    assert all(r.cwe is None for r in recs)  # qrp-mcp 0.44.0 has no CWE field


# CryptoScan v1.5.0 pkg/patterns/matcher.go L1302-1310 MAC-HMAC-SHA1-001, L1317-1324 MAC-HMAC-MD5-001
def test_cryptoscan_maps_hmac_md5_and_hmac_sha1_but_not_ambiguous_names():
    bom = {"components": [
        {"type": "cryptographic-asset", "name": n, "cryptoProperties": {"assetType": "algorithm"},
         "evidence": {"occurrences": [{"location": "sshd_config", "line": i}]}}
        for i, n in enumerate(["HMAC-MD5", "HMAC-SHA1", "SHA-1", "3DES", "Weak Certificate Signature (SHA-1)",
                               "Weak Cipher Suite"], 1)]}
    assert [r.family for r in CryptoScanAdapter.parse(bom)] == [
        "MD5", "SHA-1", "SHA-1", "3DES", "Weak Certificate Signature (SHA-1)", "Weak Cipher Suite"]


# qscan @8b737992 src/qscan/detectors/algo_risk.py L22 "SHA1", L26 "TRIPLEDES"; java_detector.py L34 "DESede"
def test_qscan_maps_its_documented_weak_names_only():
    bom = {"components": [
        {"type": "cryptographic-asset", "name": n, "cryptoProperties": {"assetType": "algorithm"},
         "properties": [{"name": "qscan:filePath", "value": "/scan/a.py"}, {"name": "qscan:lineNumber", "value": str(i)}]}
        for i, n in enumerate(["SHA1", "TRIPLEDES", "TripleDES", "DESede", "ARCFOUR", "ARC4", "SHA", "SHA1withECDSA",
                               "RC4", "MD4"], 1)]}
    assert [r.family for r in QscanAdapter.parse(bom)] == [
        "SHA-1", "3DES", "3DES", "3DES", "ARCFOUR", "ARC4", "SHA", "SHA1withECDSA", "RC4", "MD4"]


# The shared prefix rule reads "DES-EDE3-CBC" as DES; no adapter here maps it to 3DES, because no
# scanner measured documents that name. Pinned so that a change to the rule is a decision.
def test_shared_prefix_rule_on_des_names():
    assert family("DES-EDE3-CBC") == "DES" and family("3DES-EDE") == "3DES"
    assert family("HMAC-MD5") == "HMAC"  # hence the CryptoScan alias above


# semgrep-rules @16b9e6d4 metadata-schema.yaml.schm L54-61: cwe is a string or a list, pattern ^CWE-\d+.*
def test_semgrep_reads_cwe_from_rule_metadata():
    from shorlist.adapters.semgrep import cwes
    res = {"results": [
        {"check_id": "python.cryptography.security.insecure-cipher-mode-ecb.insecure-cipher-mode-ecb",
         "path": "/scan/enc.py", "start": {"line": 5},
         "extra": {"metadata": {"cwe": ["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"]}}},
        {"check_id": "x.y.two-cwes", "path": "/scan/enc.py", "start": {"line": 6},
         "extra": {"metadata": {"cwe": ["CWE-326: Inadequate Encryption Strength", "CWE-0327: x"]}}},
        {"check_id": "x.y.string-cwe", "path": "/scan/enc.py", "start": {"line": 7},
         "extra": {"metadata": {"cwe": "CWE-295: Improper Certificate Validation"}}},
        {"check_id": "x.y.no-cwe", "path": "/scan/enc.py", "start": {"line": 8}, "extra": {"metadata": {}}}]}
    recs = SemgrepAdapter.parse(res)
    assert [(r.line, r.cwe) for r in recs] == [(5, "CWE-327"), (6, "CWE-326"), (6, "CWE-327"), (7, "CWE-295"), (8, None)]
    assert cwes({"cwe": "not a cwe"}) == [] and cwes({}) == []


# semgrep-rules @16b9e6d4: use-of-sha1.yaml L2-4, insecure-cipher-algorithms-arc4.yaml L2-4,
# desede-is-deprecated.yaml L2-4 (cited in the adapter)
def test_semgrep_maps_the_weak_tokens_its_rules_define():
    assert family_from_check_id("rules.java.lang.security.audit.crypto.use-of-sha1") == "SHA-1"
    assert family_from_check_id("rules.python.cryptography.security.insecure-hash-algorithm-sha1") == "SHA-1"
    assert family_from_check_id("rules.python.cryptography.security.insecure-cipher-algorithm-arc4") == "RC4"
    assert family_from_check_id("rules.java.lang.security.audit.crypto.desede-is-deprecated") == "3DES"
    assert family_from_check_id("rules.python.pycryptodome.security.insecure-cipher-algorithm-des") == "DES"
    assert family_from_check_id("rules.java.lang.security.audit.crypto.ecb-cipher") == \
        "rules.java.lang.security.audit.crypto.ecb-cipher"


def test_out_dir_keeps_the_fixed_file_apart(tmp_path, monkeypatch):
    monkeypatch.setenv("SHORLIST_OUT_DIR", str(tmp_path / "raw"))
    a = CryptoScanAdapter()
    assert a.outdir(tmp_path / "SL-5000" / "tree", tmp_path).name == "SL-5000"
    assert a.outdir(tmp_path / "SL-5000" / "fix", tmp_path).name == "SL-5000-fix"


def test_theia_line_is_one_based():
    # theia v1.1.2 on a real RSA key whose BEGIN line is line 1 of key.pem writes line 0
    # (ShorList v0.2.0 nuli/out/theia3/CTRL-realrsatrad/cbom.json); a lineless component stays lineless
    from shorlist.adapters.cbomkit_theia import CbomkitTheiaAdapter
    bom = {"components": [
        {"type": "cryptographic-asset", "name": "RSA",
         "cryptoProperties": {"assetType": "related-crypto-material",
                              "relatedCryptoMaterialProperties": {"size": 2048}},
         "evidence": {"occurrences": [{"location": "key.pem", "line": 0}]}},
        {"type": "cryptographic-asset", "name": "ECDSA",
         "evidence": {"occurrences": [{"location": "cert.pem"}]}}]}
    assert CbomkitTheiaAdapter.parse(bom) == [Record(path="key.pem", line=1, family="RSA", size=2048),
                                              Record(path="cert.pem", line=None, family="ECDSA")]


def test_cipheriq_never_reads_a_stale_cbom(tmp_path, monkeypatch):
    # cbom-generator exits 0 when it cannot write /out/cbom.json; an old file there must not be parsed
    import subprocess
    import pytest
    monkeypatch.setenv("SHORLIST_OUT_DIR", str(tmp_path / "raw"))
    stale = {"components": [{"type": "cryptographic-asset", "name": "RSA",
                             "evidence": {"occurrences": [{"location": "/scan/key.pem", "line": 1}]}}]}
    tree = tmp_path / "SL-3596" / "tree"
    tree.mkdir(parents=True)
    for cls in (CipherIQAdapter, CipherIQServicesAdapter):
        a = cls()
        out = a.outdir(tree, tmp_path)
        (out / "cbom.json").write_text(json.dumps(stale))
        monkeypatch.setattr(a, "run_scan", lambda *args, **kw: subprocess.CompletedProcess([], 0, "", ""))
        with pytest.raises(RuntimeError, match="wrote no CBOM"):
            a.scan(tree, tmp_path)


def test_container_timeout_removes_the_container_retries_once_then_raises(tmp_path, monkeypatch):
    import subprocess
    import pytest
    from shorlist.adapters import _container
    from shorlist.adapters.base import ScannerTimeout
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(_container.subprocess, "run", fake_run)
    a = CipherIQAdapter()
    tree, out = tmp_path / "SL-2095" / "tree", tmp_path / "out"
    tree.mkdir(parents=True)
    out.mkdir()
    with pytest.raises(ScannerTimeout):
        a.run_scan(tree, out, ["/scan"], timeout=1)
    names = [c[c.index("--name") + 1] for c in calls if c[:2] == ["docker", "run"]]
    assert [c[:2] for c in calls] == [["docker", "run"], ["docker", "rm"]] * 2
    assert [c[3] for c in calls if c[:2] == ["docker", "rm"]] == names  # the container itself is removed
    assert len(set(names)) == 2 and all(n.startswith("shorlist-") for n in names)
    assert "--name" not in a.command  # the recorded command carries no per-run name

    # a timeout on the first attempt only: removed, retried, and the retry's result is used
    calls.clear()

    def once(argv, **kw):
        calls.append(argv)
        if argv[:2] == ["docker", "run"] and sum(c[:2] == ["docker", "run"] for c in calls) == 1:
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(_container.subprocess, "run", once)
    assert a.run_scan(tree, out, ["/scan"], timeout=1).stdout == "ok"
    assert [c[:2] for c in calls] == [["docker", "run"], ["docker", "rm"], ["docker", "run"]]
