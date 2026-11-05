# ShorList

**The open catalogue of the cryptographic forms Shor's algorithm breaks — and the
post-quantum ones that replace them.**

ShorList is a versioned, citable list of *forms*: the concrete ways in which a public-key
algorithm appears in source code and configuration text. Each row is one form, the minimal
file it stands in, what a scanner should report for it, and the primary source that defines
it. A generator plants every row into its own minimal tree, runs a scanner on it and scores
the output, so any cryptographic-inventory tool can be measured against the same public
denominator, repeatably.

Version **0.1.0** · data **CC BY 4.0** · generator **Apache-2.0** · status: pre-release,
not yet deposited (no DOI).

## Why

Cryptographic inventories (CBOMs) are produced by scanners, and a scanner's output says
what it found, not what it could not read. There is no shared list to measure against.
The national guidance documents that come closest say so explicitly: BSI TR-02102-1
(2026-01) states that "no claim is made to completeness", and ANSSI's guide to the
selection of cryptographic algorithms (PA-079, v1.0) says of its list that it is "ni
exhaustive, ni limitative". Registries such as
IANA's and CycloneDX's `cryptography-defs.json` enumerate names, not the forms in which
those names occur in code. ShorList is an attempt at that missing denominator, small and
checkable first.

## The unit of measure

A **form** is one way an algorithm appears in text:

| `form_kind` | example |
|---|---|
| `api_call` | `rsa.generate_private_key(public_exponent=65537, key_size=2048)` |
| `api_string` | `Signature.getInstance("SHA256withECDSA")` |
| `config_key`, `config_value` | `KexAlgorithms mlkem768x25519-sha256` in `sshd_config` |
| `registry_id` | IANA TLS SignatureScheme `ecdsa_secp256r1_sha256` |
| `oid` | `1.2.840.113549.1.1.1` (rsaEncryption) |
| `curve_name`, `cli`, `file_format` | reserved in v0.1, no rows yet |

Half of the value is in the **decoys** (`negative: true`): text that names an algorithm
but is not a use of it — a ban list, a comment, a log string, a switch set to off, an
OpenSSH `-` removal list. Decoys measure false alarms, not only misses.

A result reads, verbatim:

> Of *N* positive forms in ShorList *vX*, *scanner version* recognises *M*; of *K*
> decoys it reports *L* as a use.

broken down by `form_kind`, family and language or product.

## What it does not measure

- **It is not recall.** The catalogue is not complete and does not claim to be; *M of N*
  is recognition of the listed forms, not a share of all the cryptography that exists.
- **It is not finding in a real tree.** Each form is planted alone, in a minimal file.
  Whether a scanner reaches that file in a real repository (file types, sizes, vendored
  code, generated code, archives) is a different measurement — coverage — and is not
  made here.
- **It does not measure misuse.** Static IVs, weak randomness, insecure modes and other
  context- or data-flow-dependent defects are out of scope.
- **Role and key size are reported beside the outcome**, not folded into it.

## Scope of v0.1

- Families: RSA, ECDSA and ML-KEM (including the X25519+ML-KEM-768 hybrids, scored on the
  post-quantum half). The closed vocabulary in [`schema/families.yaml`](schema/families.yaml)
  already lists the rest of the v1 scope — DSA, DH, EC, ECDH, EdDSA, X25519, X448, ML-DSA,
  SLH-DSA, LMS, XMSS — with their CycloneDX mapping.
- Languages and products: Python (pyca/cryptography), Java (JCA), Go (standard library),
  nginx, OpenSSH `sshd`, IANA TLS / SSH / JOSE identifiers, one OID.
- 30 rows: 20 positive forms and 10 decoys.

**Known not covered in v0.1:** C/C++ (OpenSSL, BoringSSL, wolfSSL…), .NET, Rust, JavaScript,
BouncyCastle, PyCryptodome; curve names; OIDs beyond one; CLI invocations; key and
certificate file formats; IKE/IPsec and vendor network configuration; DSA, DH, EdDSA and
the post-quantum signatures; classically weak algorithms (SHA-1, MD5, 3DES, RSA < 2048),
planned for v2 against OWASP ASVS 5.0 Appendix C and NIST SP 800-131A Rev. 2.

## A row

Rows live in [`forms/`](forms/), one YAML file per row, validated by
[`schema/form.schema.json`](schema/form.schema.json) (JSON Schema 2020-12):

| field | meaning |
|---|---|
| `id` | `SL-0001`… stable, never reused |
| `family`, `cyclonedx_family` | closed vocabulary; the CycloneDX family when the form pins one (`SHA256withRSA` → `RSASSA-PKCS1`) |
| `parameter_set`, `role` | what the literal pins |
| `form_kind`, `language_or_product` | see above |
| `literal` | the exact text, one line |
| `context_filename`, `context_template` | the minimal file the literal is planted in, under that name (`sshd_config`, `Main.java`) |
| `expected` | `family`, `role`, `size` a scanner should report (for a decoy: what it would wrongly report) |
| `negative`, `decoy_class` | decoy and its class |
| `source` | one or more **primary** sources: URL, section, date read |
| `status` | `verified-source` (checked against the source) or `verified-run` (checked by running the product); `withdrawn` rows are kept |
| `added_by`, `added_at`, `reviewed_by`, `notes` | provenance |

Unverified suggestions go to [`candidates/`](candidates/), never into `forms/`.

## Running the generator

Requires Python ≥ 3.10, `pyyaml`, `jsonschema`. No network access is used.

```sh
pip install -r requirements.txt
cd generator
python -m shorlist validate                     # schema + template syntax, every row
python -m shorlist run --adapter qrp-mcp \
    --command "uvx qrp-mcp@0.44.0" \
    --out ../results/qrp-mcp-0.44.0.json --md ../results/qrp-mcp-0.44.0.md
python -m shorlist table ../results/qrp-mcp-0.44.0.json
```

**Scoring.** For a positive row, only records on the literal's line in the planted file,
reported as a use, count: `hit` (the expected family), `parent_only` (only `EC` for an
expected ECDSA/ECDH), `wrong_family`, or `miss`. For a decoy, any in-scope family reported as
a use anywhere in the planted tree is a `false_alarm`; reporting it as *not* a use (comment,
ban) is correct. The full rules are in [`generator/shorlist/score.py`](generator/shorlist/score.py).

**Template syntax.** "Parses" means syntax, not compilation: Python `ast.parse`, Go
`gofmt -e`, Java `javac` (CI uses JDK 25), shell `sh -n`, and a line-shape check for
nginx, `sshd_config` and `java.security`. See
[`generator/shorlist/parsecheck.py`](generator/shorlist/parsecheck.py).

**Repeatability.** Every result carries the catalogue version and **catalogue sha256**
(sha256 over each `forms/*.yaml` in sorted path order: path, NUL, bytes, NUL), the
generator version, the scanner's own version string, and a **fingerprint**: sha256 of the
canonical JSON of `{catalogue_sha256, generator_version, scanner_version, rows: [[id,
outcome, role_ok, size_ok], …]}`. The same catalogue, generator and scanner give the same
fingerprint; the run date and host are recorded but are not part of it.

### Adding a scanner

Write an adapter in [`generator/shorlist/adapters/`](generator/shorlist/adapters/): a class
with `version()` and `scan(tree, workdir) -> list[Record]`, registered in `ADAPTERS`. A
`Record` is `{path, line, family, role, size, is_use}`; the interface is documented in
[`adapters/base.py`](generator/shorlist/adapters/base.py) and
[`adapters/qrp_mcp.py`](generator/shorlist/adapters/qrp_mcp.py) is a worked example. The
adapter is the only place that knows the scanner's field names; the scorer sees records only.

## Results

| scanner | positive forms recognised | decoys reported as a use | fingerprint |
|---|---|---|---|
| qrp-mcp 0.44.0 | 20 / 20 | 0 / 10 | see [`results/`](results/) |

Role is wrong on 2 of the 16 rows where a role is expected: for `TLS_RSA_WITH_AES_128_GCM_SHA256`
and its OpenSSL name `AES128-GCM-SHA256`, qrp-mcp reports RSA as key establishment only;
the suite uses RSA for both key transport and authentication. Measurements of other
scanners are welcome as pull requests to `results/`, produced by the generator.

## Contributing rows

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: one row per pull request, a primary
source with section and date read, a template that parses, and a decoy where one is
natural. CI checks the schema and the template syntax. **A row is never rejected because a
scanner — including the initiator's — does not recognise it**; the qrp-mcp run in CI is
informational only. Every row needs **two reviewers** before it is merged. A row found to
be wrong is **withdrawn, not deleted**: it stays with `status: withdrawn`, the reason and
the date, so that what the catalogue once claimed remains on record.

## Conflict of interest

ShorList was started by Stanimir Tenev of Elkan Electronic, who also writes qrp-mcp, one of
the scanners it can measure. To keep that from shaping the denominator: the catalogue's
rules do not depend on any scanner's output; rows are admitted on their primary source,
not on whether qrp-mcp detects them; qrp-mcp's own misses are published in `results/`
like anyone else's; and other scanners are measured and named in the same table. Reviews
from people with no tie to Elkan Electronic are explicitly sought.

## Citing

See [`CITATION.cff`](CITATION.cff). Until a DOI is minted:

> Tenev, S. *ShorList: an open catalogue of cryptographic forms*, version 0.1.0, 2026.

## Licences

- Catalogue data (`forms/`, `schema/`, `results/`): [CC BY 4.0](LICENSE-DATA).
- Generator and tests (`generator/`, `tests/`, CI): [Apache-2.0](LICENSE).
