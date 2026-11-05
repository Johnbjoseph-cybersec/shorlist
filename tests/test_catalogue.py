import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "generator"))

from shorlist.catalogue import (  # noqa: E402
    catalogue_sha256, form_files, literal_line, load, load_families, load_schema, validate_row,
)
from shorlist.parsecheck import FAIL, check  # noqa: E402

SCHEMA, FAMILIES = load_schema(), load_families()
ROWS = load(include_withdrawn=True)


def first_row():
    return copy.deepcopy(yaml.safe_load(form_files()[0].read_text()))


def test_catalogue_loads_and_is_v1_shape():
    assert len(ROWS) >= 30
    assert sum(r["negative"] for r in ROWS) >= 10


def test_every_template_parses():
    bad = [(r["id"], d) for r in ROWS for s, d in [check(r["context_filename"], r["context_template"])] if s == FAIL]
    assert bad == []


def test_literal_is_on_one_line_of_template():
    for r in ROWS:
        assert r["literal"] in r["context_template"].split("\n")[literal_line(r) - 1]


def test_valid_row_passes():
    assert validate_row(first_row(), None, SCHEMA, FAMILIES) == []


def test_bad_form_kind_rejected():
    r = first_row()
    r["form_kind"] = "regex"
    assert any("form_kind" in e for e in validate_row(r, None, SCHEMA, FAMILIES))


def test_bad_family_rejected():
    r = first_row()
    r["family"] = r["expected"]["family"] = "Kyber"
    assert validate_row(r, None, SCHEMA, FAMILIES)


def test_missing_source_rejected():
    r = first_row()
    del r["source"]
    assert any("source" in e for e in validate_row(r, None, SCHEMA, FAMILIES))


def test_empty_source_rejected():
    r = first_row()
    r["source"] = []
    assert validate_row(r, None, SCHEMA, FAMILIES)


def test_source_needs_date_read():
    r = first_row()
    del r["source"][0]["read_at"]
    assert validate_row(r, None, SCHEMA, FAMILIES)


def test_unverified_status_rejected():
    r = first_row()
    r["status"] = "agent-said"
    assert validate_row(r, None, SCHEMA, FAMILIES)


def test_withdrawn_needs_reason_and_date():
    r = first_row()
    r["status"] = "withdrawn"
    assert validate_row(r, None, SCHEMA, FAMILIES)
    r["withdrawn_reason"] = "the documented name was changed upstream"
    r["withdrawn_at"] = "2026-12-01"
    assert validate_row(r, None, SCHEMA, FAMILIES) == []


def test_decoy_needs_class():
    r = next(copy.deepcopy(x) for x in ROWS if x["negative"])
    del r["decoy_class"]
    assert validate_row(r, None, SCHEMA, FAMILIES)


def test_literal_must_occur_in_template():
    r = first_row()
    r["literal"] = "not in the template"
    assert any("verbatim" in e for e in validate_row(r, None, SCHEMA, FAMILIES))


def test_cyclonedx_family_must_map():
    r = first_row()
    r["cyclonedx_family"] = "ML-DSA"
    assert any("cyclonedx_family" in e for e in validate_row(r, None, SCHEMA, FAMILIES))


def test_schema_enum_matches_families_yaml():
    assert set(SCHEMA["$defs"]["family"]["enum"]) == set(FAMILIES)


def test_catalogue_hash_is_stable_and_content_sensitive(tmp_path):
    h = catalogue_sha256()
    assert h == catalogue_sha256()
    for sub in ("forms", "schema"):
        (tmp_path / sub).mkdir()
    for p in form_files():
        (tmp_path / "forms" / p.name).write_bytes(p.read_bytes())
    assert catalogue_sha256(tmp_path) == h
    p = sorted((tmp_path / "forms").glob("*.yaml"))[0]
    p.write_bytes(p.read_bytes() + b"\n")
    assert catalogue_sha256(tmp_path) != h


@pytest.mark.parametrize("name,text,ok", [
    ("a.py", "x = (\n", False),
    ("nginx.conf", "http {\n  ssl_ciphers HIGH\n}\n", False),
    ("sshd_config", "KexAlgorithms\n", False),
    ("java.security", "no equals sign here\n", False),
    ("unknown.xyz", "", False),
    ("Keys.cs", "class Keys {\n", False),
    ("swanctl.conf", "connections {\n  proposals aes128\n}\n", False),
    ("httpd.conf", "<VirtualHost *:443>\n  SSLEngine on\n", False),
    ("fortigate.conf", "config vpn ipsec phase1-interface\n", False),
    ("running-config", "crypto ikev2 proposal P\n group 19\n", False),
    ("a.c", "#include <mbedtls/pk.h>\nint main(void) {\n", False),
    ("a.c", "int main(void) { return 0 }\n", False),
    ("mbedtls_config.h", "#define X 1\nint f( {\n", False),
    ("a.cpp", "#include <botan/rsa.h>\nint main() { return (0; }\n", False),
    ("a.rs", "fn main() {\n", False),
    ("keys.php", "<?php\nfunction f() {\n", False),
    ("keys.rb", "def f(\n", False),
    ("Keys.kt", "fun main() {\n", False),
    ("Keys.swift", "func makeKey() {\n    let key = P256.Signing.PrivateKey(\n}\n", False),
    ("keys.rb", "require \"openssl\"\n\nrsa = OpenSSL::PKey::RSA.new(2048)\n", True),
    ("a.py", "x = 1\n", True),
    ("a.rs", "use ring::agreement;\n\nfn main() {\n    let alg = &agreement::X25519;\n}\n", True),
    ("a.c", "#include <mbedtls/pk.h>\n\nint main(void)\n{\n    return 0;\n}\n", True),
])
def test_parsecheck_rejects_broken_templates(name, text, ok):
    assert (check(name, text)[0] != FAIL) is ok
