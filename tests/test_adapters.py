"""Parsing tests for the container adapters, on the output shapes their documentation shows.
No docker needed: only parse() and the command plumbing are exercised."""
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
    assert Record("src/crypto.js", 12, "sha-256") in recs
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
    assert recs[1].family.endswith("insecure-hash-algorithm-md5")
    assert family_from_check_id("go.lang.security.audit.crypto.use_of_weak_rsa_key.use-of-weak-rsa-key") == "RSA"
