#!/bin/sh
# Generate the throwaway key material planted in the PEM rows of forms/ and write it into
# their context_template, keeping the BEGIN line (the row's literal) on line 1.
#
# These keys are PUBLISHED ON PURPOSE. They exist only so that a scanner that recognises a key
# by parsing it has something real to parse. They protect nothing and are used nowhere.
# Secret scanners will flag them; see "Test keys" in README.md.
#
# Usage: tools/make_test_keys.sh [workdir]     (run from the repository root; needs openssl 3
#        and python3 with pyyaml). Each run makes new keys, so the catalogue sha256 changes.
# The keys themselves are committed as data in forms/; this script records how they were made.
set -eu

OUT=${1:-$(mktemp -d)}
mkdir -p "$OUT"
cd "$OUT"
q() { "$@" 2>/dev/null; }

# SL-3596  RSA PRIVATE KEY      PKCS #1 RSAPrivateKey, 2048 bits ("traditional" PEM)
q openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-a.p8
q openssl pkey -in rsa-a.p8 -traditional -out SL-3596.pem
# SL-3597  RSA PUBLIC KEY       PKCS #1 RSAPublicKey, 2048 bits (of a second key, whose private half is discarded)
q openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-b.p8
q openssl rsa -in rsa-b.p8 -RSAPublicKey_out -out SL-3597.pem
# SL-3600  DSA PARAMETERS       2048-bit p, FIPS 186-4 generation
q openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out SL-3600.pem
# SL-3598  DSA PRIVATE KEY      OpenSSL's traditional DSAPrivateKey, 2048 bits (own parameters)
q openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsa-a.par
q openssl genpkey -paramfile dsa-a.par -out dsa-a.p8
q openssl pkey -in dsa-a.p8 -traditional -out SL-3598.pem
# SL-3599  DSA PUBLIC KEY       2048 bits; no openssl command writes this label, so libcrypto's own
#          "type-specific" PEM encoder is called (OSSL_ENCODER_CTX_new_for_pkey(..., "PEM", "type-specific"))
q openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsa-b.par
q openssl genpkey -paramfile dsa-b.par -out dsa-b.p8
python3 - dsa-b.p8 SL-3599.pem <<'PY'
import ctypes, ctypes.util, sys
c = ctypes.CDLL(ctypes.util.find_library("crypto"))
c.BIO_new_file.restype = ctypes.c_void_p
c.BIO_new_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
c.BIO_free.argtypes = [ctypes.c_void_p]
c.PEM_read_bio_PrivateKey.restype = ctypes.c_void_p
c.PEM_read_bio_PrivateKey.argtypes = [ctypes.c_void_p] * 4
c.OSSL_ENCODER_CTX_new_for_pkey.restype = ctypes.c_void_p
c.OSSL_ENCODER_CTX_new_for_pkey.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
c.OSSL_ENCODER_to_bio.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
b = c.BIO_new_file(sys.argv[1].encode(), b"r")
k = c.PEM_read_bio_PrivateKey(b, None, None, None)
PUBLIC_KEY = 0x86  # OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS (= EVP_PKEY_PUBLIC_KEY)
ctx = c.OSSL_ENCODER_CTX_new_for_pkey(k, PUBLIC_KEY, b"PEM", b"type-specific", None)
o = c.BIO_new_file(sys.argv[2].encode(), b"w")
ok = k and ctx and c.OSSL_ENCODER_to_bio(ctx, o)
c.BIO_free(o)
sys.exit(0 if ok else "libcrypto could not encode the DSA public key")
PY
# SL-3601  EC PRIVATE KEY       RFC 5915 ECPrivateKey on P-256 (prime256v1), named curve
q openssl ecparam -genkey -name prime256v1 -noout -out SL-3601.pem
# SL-3602  EC PARAMETERS        P-256 as a named-curve OID (the default encoding; the body is short and real)
q openssl ecparam -name prime256v1 -out SL-3602.pem
# SL-3603  ECDSA PUBLIC KEY     P-256 SubjectPublicKeyInfo under the label "ECDSA PUBLIC KEY": pem.h defines
#          the label (PEM_STRING_ECDSA_PUBLIC) but OpenSSL 3 neither writes nor reads it, so the
#          body is the SPKI that `openssl ec -pubout` writes, relabelled
q openssl ecparam -genkey -name prime256v1 -noout -out ec-b.pem
q openssl ec -in ec-b.pem -pubout -out ec-b.pub
sed 's/PUBLIC KEY-----$/ECDSA PUBLIC KEY-----/' ec-b.pub > SL-3603.pem
# SL-3604  DH PARAMETERS        PKCS #3 DHParameter, freshly generated 2048-bit safe prime, g = 2
q openssl dhparam -out SL-3604.pem 2048
# SL-3616  X9.42 DH PARAMETERS  X9.42 DomainParameters, 2048-bit p, FIPS 186-4 generation
q openssl genpkey -genparam -algorithm DHX -pkeyopt dh_paramgen_prime_len:2048 -out SL-3616.pem

# SL-3637..3646: the generic labels, written with default settings. ML-KEM and ML-DSA need
# OpenSSL 3.5 or newer; its default private-key output is seed-priv (RFC 9935 / RFC 9881 "both").
# SL-3637  PRIVATE KEY          PKCS #8, RSA-2048
q openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out SL-3637.pem
# SL-3638  PRIVATE KEY          PKCS #8, id-ecPublicKey on P-256
q openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out SL-3638.pem
# SL-3639  PRIVATE KEY          PKCS #8, Ed25519 (RFC 8410)
q openssl genpkey -algorithm ED25519 -out SL-3639.pem
# SL-3640  PUBLIC KEY           SubjectPublicKeyInfo, RSA-2048 (of a key whose private half is discarded)
q openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-e.p8
q openssl pkey -in rsa-e.p8 -pubout -out SL-3640.pem
# SL-3641  CERTIFICATE          self-signed, RSA-2048, sha256WithRSAEncryption
q openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa-f.p8 -subj "/CN=ShorList test RSA" -days 3650 -sha256 -out SL-3641.pem
# SL-3642  CERTIFICATE          self-signed, P-256, ecdsa-with-SHA256
q openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec-g.p8 -subj "/CN=ShorList test P-256" -days 3650 -sha256 -out SL-3642.pem
# SL-3643  PRIVATE KEY          PKCS #8, ML-KEM-768, seed and expanded key
q openssl genpkey -algorithm ML-KEM-768 -out SL-3643.pem
# SL-3644  PUBLIC KEY           SubjectPublicKeyInfo, ML-KEM-768 (private half discarded)
q openssl genpkey -algorithm ML-KEM-768 -out mlkem-a.p8
q openssl pkey -in mlkem-a.p8 -pubout -out SL-3644.pem
# SL-3645  PRIVATE KEY          PKCS #8, ML-DSA-65, seed and expanded key
q openssl genpkey -algorithm ML-DSA-65 -out SL-3645.pem
# SL-3646  CERTIFICATE          self-signed, ML-DSA-65
q openssl req -x509 -newkey ML-DSA-65 -nodes -keyout mldsa-a.p8 -subj "/CN=ShorList test ML-DSA-65" -days 3650 -out SL-3646.pem

rm -f rsa-a.p8 rsa-b.p8 dsa-a.p8 dsa-b.p8 ec-b.pem   # private halves not planted anywhere
rm -f rsa-e.p8 rsa-f.p8 ec-g.p8 mlkem-a.p8 mldsa-a.p8
cd - >/dev/null

python3 - "$OUT" <<'PY'
import sys
from pathlib import Path
import yaml

out = Path(sys.argv[1])
MARK = {True: "ShorList public test key: deliberately published, never used anywhere, protects nothing.",
        False: "ShorList public test parameters: deliberately published, never used anywhere."}
CERT_MARK = "ShorList public test certificate: deliberately published, never used anywhere, protects nothing."
for pem in sorted(out.glob("SL-*.pem")):
    rid, text = pem.stem, pem.read_text()
    f = Path("forms") / f"{rid}.yaml"
    row = yaml.safe_load(f.read_text())
    if text.splitlines()[0] != row["literal"]:
        sys.exit(f"{rid}: generated first line {text.splitlines()[0]!r} is not the literal {row['literal']!r}")
    mark = (CERT_MARK if "CERTIFICATE" in row["literal"] else MARK["PARAMETERS" not in row["literal"]])
    body = text.rstrip("\n") + "\n" + mark + "\n"
    src = f.read_text()
    head, rest = src.split("context_template: |\n", 1)
    old, tail = rest.split("expected:\n", 1)
    new = "".join("  " + line + "\n" for line in body.splitlines())
    f.write_text(head + "context_template: |\n" + new + "expected:\n" + tail)
    assert yaml.safe_load(f.read_text())["context_template"] == body, rid
    print(f"{rid}: {text.splitlines()[0]}  ({len(text.splitlines()) - 2} body lines)")
PY
