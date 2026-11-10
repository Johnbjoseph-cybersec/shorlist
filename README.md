# ShorList

**An open catalogue of the cryptographic forms Shor's algorithm breaks — and the
post-quantum ones that replace them.**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23974515.svg)](https://doi.org/10.5281/zenodo.23974515)
[![Data: CC BY 4.0](https://img.shields.io/badge/data-CC%20BY%204.0-lightgrey.svg)](LICENSE-DATA)
[![Code: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg)](LICENSE)
[![Version 0.2.0](https://img.shields.io/badge/version-0.2.0-informational.svg)](VERSION)
[![Rows: 2035](https://img.shields.io/badge/rows-2035-success.svg)](forms/)
[![ci](https://github.com/shorlist/shorlist/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shorlist/shorlist/actions/workflows/ci.yml)

For **scanner vendors**, who want to show what their tool recognises against a public list,
and for **firms that buy scanners**, who want to compare tools on the same rows before they
choose one.

ShorList is a versioned, citable list of *forms*: the concrete ways in which a public-key
algorithm appears in source code and configuration text. Each row is one form, the minimal
file it stands in, what a scanner should report for it, and the primary source that defines
it. A generator plants every row into its own minimal tree, runs a scanner on it and scores
the output, so any cryptographic-inventory tool can be measured against the same public
denominator, repeatably.

Since v0.2 the catalogue is scored on **three axes, reported apart**: *quantum* (the
headline: Shor-vulnerable and post-quantum forms), *weak* (classically weak algorithms and
parameters, anchored on NIST SP 800-131A Rev. 2 and similar) and *defect* (misuse such as
ECB, a constant IV or disabled certificate validation, scored on the CWE). A scanner gains
or loses nothing on the quantum axis for a weak or a defect row.

```mermaid
flowchart LR
    C["ShorList v0.2.0<br/>2035 rows, a primary source on each"] --> Q["quantum<br/>1537 rows (169 decoys)<br/>Shor-vulnerable + post-quantum"]
    C --> W["weak<br/>311 rows (31 decoys)<br/>SHA-1, MD5, 3DES, RSA-1024 …"]
    C --> D["defect<br/>187 rows (25 decoys)<br/>misuse, scored on the CWE"]
```

Version **0.2.0** · data **CC BY 4.0** · generator **Apache-2.0** · DOI [10.5281/zenodo.23974515](https://doi.org/10.5281/zenodo.23974515)
(all versions).

**Contents:** [Quick start](#quick-start) · [Use it](#use-it) · [Why](#why) ·
[The unit of measure](#the-unit-of-measure) · [What it does not measure](#what-it-does-not-measure) ·
[Scope of v0.2](#scope-of-v02) · [A row](#a-row) · [Running the generator](#running-the-generator) ·
[Results](#results) · [Contributing rows](#contributing-rows) ·
[Conflict of interest](#conflict-of-interest) · [Citing](#citing) · [Licences](#licences)

## Quick start

```sh
pip install -r requirements.txt qrp-mcp==0.44.0
cd generator
python -m shorlist validate                                   # schema + template syntax, every row
python -m shorlist run --adapter qrp-mcp --out ../run.json --md ../run.md
```

Any adapter in [`generator/shorlist/adapters/`](generator/shorlist/adapters/) runs the same
way; see [Running the generator](#running-the-generator) for the full options.

## Use it

- **Score your scanner**: write or pick an adapter and run the generator, as in
  [Quick start](#quick-start) and [Adding a scanner](#adding-a-scanner).
- **Filter to your stack**: run only the rows for your languages and products. *Planned for
  v0.3.*
- **Add it to CI**: a GitHub Action that scores a scanner on every pull request. *Planned for
  v0.3.*

## Why

Cryptographic inventories (CBOMs) are produced by scanners, and a scanner's output says
what it found, not what it could not read. Shared test sets exist for crypto-API misuse
(CryptoAPI-Bench, CamBench, OWASP Benchmark) and a few small quantum-labelled corpora, but
we know of no open list of the forms in code and configuration, scored on a quantum axis of
its own, with decoys and a primary source on every row, to measure against.
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
| `curve_name` | `CURVE = "P-384"` |
| `cli` | `openssl genpkey -algorithm RSASSA-PSS -out key.pem` |
| `file_format` | the PEM label `-----BEGIN RSA PRIVATE KEY-----` |

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
- **Misuse only where one line shows it.** The defect axis holds misuse that a single
  line pins (`AES/ECB/…`, an all-zero IV literal, `verify=False`, 100 PBKDF2 iterations).
  Misuse that depends on data flow across functions or files (a key that reaches
  `Cipher.init` from a constant three calls away, an IV reused across messages at run
  time) is not in the catalogue.
- **Role and key size are reported beside the outcome**, not folded into it.

## Scope of v0.2

2035 rows, every one checked against a primary source; 75 more wait in
[`candidates/`](candidates/) (no primary source yet, or no family in the vocabulary).

| axis | rows | positive | decoys | families |
|---|---|---|---|---|
| quantum | 1537 | 1368 | 169 | RSA, DSA, DH, EC, ECDSA, ECDH, EdDSA, X25519, X448, ML-KEM, ML-DSA, SLH-DSA, LMS, XMSS |
| weak | 311 | 280 | 31 | SHA-1, MD5, MD4, DES, 3DES, RC4, RC2, and weak parameters of quantum families (RSA-1024, DH-1024, P-192 …) |
| defect | 187 | 162 | 25 | 14 CWE classes, e.g. CWE-327 (ECB, old TLS), CWE-321 (hard-coded key), CWE-295 (certificate validation off), CWE-780 (RSA without OAEP), CWE-916 (too few iterations), CWE-323 (nonce reuse) |

Languages and products: Python, Java, Kotlin, Go, C, C++, C#, Rust, JavaScript/Node,
PHP, Ruby, Swift; OpenSSL C API and CLI; nginx, Apache httpd, OpenSSH, strongSwan, Caddy,
Traefik, OpenVPN; Terraform, AWS CloudFormation, AWS/Azure/Google Cloud KMS, HashiCorp
Vault, cert-manager, PKCS#11; IANA TLS, SSH, IKEv2, JOSE and COSE identifiers; OIDs, curve
names, PEM and JWK. Wave 6 took forms and misuse classes from the scientific literature
(MASC, CryptoAPI-Bench, CryptoGuard, Egele et al., LICMA, a Go misuse study, PQC-migration
studies), each with the paper and a primary definition as sources; `defect.taxonomy` names
the same class in those benchmarks.

**Known not covered in v0.2:** misuse that needs data flow (see above); families with no
entry in the vocabulary yet (Streamlined NTRU Prime, pre-standard Kyber names, SM2/SM3/SM4,
GOST, Blowfish, IDEA, bcrypt/scrypt/Argon2); vendor network configuration beyond a few
FortiOS and Junos lines; binaries and archives.

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
| `weakness` | weak axis: `status` (disallowed, deprecated, legacy_use), the standard and section that say so, and a quote |
| `row_kind`, `defect` | `defect` for a misuse row; `defect.cwe` is what a scanner must report, `defect.taxonomy` the same class in other benchmarks |
| `right_template` | positive defect rows: the same file with the defect fixed; reporting a CWE on it is a false alarm |
| `source` | one or more **primary** sources: URL, section, date read |
| `status` | `verified-source` (checked against the source) or `verified-run` (checked by running the product); `withdrawn` rows are kept |
| `added_by`, `added_at`, `reviewed_by`, `notes` | provenance |

Unverified suggestions go to [`candidates/`](candidates/), never into `forms/`.

### Test keys

The ten positive PEM rows (SL-3596 to SL-3604 and SL-3616: RSA, DSA and EC keys, DSA, EC and
DH parameters) carry **real key material, generated for ShorList and published on purpose**.
It is throwaway material: it protects nothing, is used nowhere, and must never be trusted. A
line after each END line says so. It is there because some tools recognise a key only by
parsing it, and a placeholder body gives them nothing to parse (drafts of v0.2.0 used the body
`VGhpcyBpcyBub3QgYSBrZXku`, "This is not a key."). The label on line 1 is still the row's
literal, so `expected` is unchanged; the key size the body happens to have (RSA-2048, DSA-2048,
P-256, 2048-bit DH) is not scored, because the label does not pin it. The commands are in
[`tools/make_test_keys.sh`](tools/make_test_keys.sh); the keys themselves are data in
`forms/`, and the private halves of the public-key rows were not kept.
**Secret scanners will flag these files.** That is expected: they are listed in
[`.github/secret_scanning.yml`](.github/secret_scanning.yml) (`paths-ignore`) and in
[`.gitleaks.toml`](.gitleaks.toml), by file, not by folder. The decoy SL-3605 is an error
message that names the label and has no body; it stays that way.

SL-3637 to SL-3646 are the generic labels: `PRIVATE KEY` (PKCS #8 / OneAsymmetricKey), `PUBLIC
KEY` (SubjectPublicKeyInfo) and `CERTIFICATE`, for RSA-2048, P-256, Ed25519, ML-KEM-768 and
ML-DSA-65, as `openssl genpkey`, `openssl pkey -pubout` and `openssl req -x509` write them with
default settings (OpenSSL 3.5 or newer for ML-KEM and ML-DSA; the PKCS #8 bodies hold the seed
and the expanded key, RFC 9935 and RFC 9881 `both`). Here the label does not name the
algorithm: the AlgorithmIdentifier in the body does, so the body pins `expected` (family, and
the key size where there is one), still scored on the BEGIN line. They are made by the same
script and listed in the same two files. SL-3647 is the ML-KEM counterpart of SL-3605.

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
ban) is correct. "In scope" follows the axis: a quantum row counts only quantum families
(a reported MD5 is ignored), a weak row counts quantum and classically weak families. A
defect row is scored on the CWE: `hit` when the scanner reports `defect.cwe` on the
literal's line, `wrong_class` for another CWE there, `miss` otherwise; the fixed file is
planted and scanned separately, and any CWE reported on it is a `false_alarm`.

**File-level findings (`file_only`).** A positive row with nothing in scope on the literal's
line, but where the scanner reports the expected family as a use in the planted file *with no
line* (line `null` or `0`), is `file_only`. It is reported in its own column
(`summary.positive.file_only`, `axes.weak.positive.file_only`, `file_only` in every `by_*`
cell) and is **not a hit**: the headline figure stays line-exact. A lineless parent family or other family is still a
`miss`. It exists because some tools (CipherIQ cbom-generator, CBOMkit-theia for certificates)
report a key or a certificate per file, not per line.

**Rows not scored (`scanner_error`).** A container scan that times out is stopped with `docker
rm -f` and retried once; if the retry also times out, the row is recorded as `scanner_error`
with the reason in `error`. Such rows are not a `miss` (the tool did not finish, so it neither
found nor missed anything): they are listed in `scanner_error: {n, ids}` (top level, in
`summary` and in each axis), left out of every `n` in `summary`, `axes` and `by_*`, and the
statement names them. `catalogue.positive` / `catalogue.decoys` still count the catalogue in
full. Both outcomes came with result format 0.3. The full rules are in [`generator/shorlist/score.py`](generator/shorlist/score.py).

**Template syntax.** "Parses" means syntax, not compilation: Python `ast.parse`, Go
`gofmt -e`, Java `javac` (CI uses JDK 25), C/C++ `gcc -fsyntax-only`, Rust `rustfmt`,
Node `node --check`, PHP `php -l`, Ruby `ruby -c`, shell `sh -n`, YAML/JSON loading, and a
line-shape check for nginx, Apache, `sshd_config`, strongSwan, FortiOS, Cisco IOS,
OpenSSL `.cnf`, PEM, `authorized_keys`, `known_hosts` and `java.security`. C#, Kotlin and
Swift get only a balanced-brace check. See
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
`Record` is `{path, line, family, role, size, is_use, cwe}`; the interface is documented in
[`adapters/base.py`](generator/shorlist/adapters/base.py) and
[`adapters/qrp_mcp.py`](generator/shorlist/adapters/qrp_mcp.py) is a worked example. The
adapter is the only place that knows the scanner's field names; the scorer sees records only.

## Network axis (live servers)

Rows whose product terminates a network protocol can also be measured from the outside, with
network scanners, on a fourth axis reported apart from the other three. The row's configuration is
planted as a **running server** in a container, and the scanner is pointed at it.

- **What must be seen.** [`generator/shorlist/live/wire.yaml`](generator/shorlist/live/wire.yaml)
  maps each such row to the items on the wire: the TLS group, cipher suite or signature scheme
  (IANA name and code point, e.g. group `0x11EC` X25519MLKEM768) or the SSH name
  (`mlkem768x25519-sha256`), each with its registry, date read and the registry line as a quote.
  `expect: seen` for a positive row; `expect: not_seen` for a removal or ban decoy
  (`KexAlgorithms -diffie-hellman-group1-sha1`, `HIGH:!kRSA`). `forms/` is not changed.
- **Planting.** OpenSSH 10.3p1 (`sshd_config` verbatim, after three `HostKey` lines and
  `PerSourcePenalties no`), nginx 1.30.6 (`nginx.conf` verbatim), Apache httpd 2.4.69 (the fragment
  included from a fixed preamble that only loads modules), and `openssl s_server` 3.5.9 for the OpenSSL C
  API rows (the string given to `SSL_CTX_set1_groups_list` / `SSL_CTX_set1_sigalgs_list` is passed to
  `-groups` / `-sigalgs`). Servers and scanners are pinned by digest and run on a
  `docker network create --internal` network, two containers at a time.
- **Reference client.** Before any scanner, `openssl s_client`, `ssh -vv` and a raw TLS 1.2 ClientHello
  ([`live/probe.py`](generator/shorlist/live/probe.py)) check whether each item really is on the wire.
  A positive row whose item is not (`not_offered`) or a decoy whose item is (`expectation_contradicted`)
  is not scored, so a miss is always a miss of something the server offers.
- **Outcomes.** `hit`, `miss`, `false_alarm` (a `not_seen` item reported), `ok` (a decoy not reported),
  `scanner_error`, and, not scored: `not_runnable` (`cloud`, `appliance`, `config_rejected` with the
  server's own error, `not_attempted`) and `not_scored` (`not_on_wire`, `comment_decoy`, `no_scanner`,
  `not_offered`, `expectation_contradicted`). A comment decoy is not a wire decoy: the line has no effect
  and the server's default set, which may include the algorithm, is what a scanner sees.
- **Adapters.** ssh-audit, testssl.sh, sslyze, nmap (`ssl-enum-ciphers`, `ssh2-enum-algos`) and Zeek
  (passive: the pcap of one broad handshake by the reference client; Zeek logs the negotiated values,
  not the server's offer). Each has a positive control: one row it must catch and one decoy.
- **Not measured.** IANA registry rows, code rows and key-management rows have no server to start.
  Cloud rows (AWS load balancer policies, ACM, cert-manager) and appliance rows (FortiOS, Junos) cannot
  be stood up locally. strongSwan rows are mapped to IKEv2 transform IDs, but none of the adapters
  enumerates IKEv2 proposals.

```sh
cd generator
python -m shorlist live --stats                                     # what wire.yaml maps
python -m shorlist live --adapter ssh-audit --adapter nmap --server openssh \
    --out-dir ../results/live                                       # one <adapter>.json/.md each
python -m shorlist live --table ../results/live/ssh-audit.json
```

The fingerprint of a live result is sha256 over wire.yaml's sha256, the catalogue sha256, the
generator and scanner versions, the image digests and the ordered `[id, outcome, reason]` rows.
Results are in [`results/live/`](results/live/).

## Results

Measured on ShorList 0.2.0, catalogue sha256 `5d0e18007d740318…`, all on the same rows. The
v0.1 results (30 rows, quantum axis only) stay in [`results/v0.1.1/`](results/v0.1.1/).

A 0 here means the tool reported none of these forms in this setup; it is not a judgement of the tool for its own purpose.

### Source-code scanners

Quantum axis: 1368 positive forms, 169 decoys. **Without registry rows** leaves out the 552
`registry_id` rows (IANA TLS, SSH, IKEv2, JOSE and COSE identifiers): a tool that builds its
name tables from the same registries finds them by construction, so the remaining 816 rows
are the fairer comparison. Both columns are always given.

| scanner | quantum: hit / 1368 | without registry rows: hit / 816 | decoys reported as a use / 169 | parent only | weak: hit / 280 (false alarm / 31) | defect: hit / 162 | result |
|---|---|---|---|---|---|---|---|
| qrp-mcp 0.44.0 | 1092 | 604 | 26 | 55 | 247 (0) | 0 | [md](results/v0.2.0/qrp-mcp-0.44.0.md) |
| CSNP CryptoScan v1.5.0 | 257 | 198 | 45 | 127 | 123 (14) | 0 | [md](results/v0.2.0/cryptoscan-1.5.0.md) |
| qscan 1.0.0 ([EthanCratchley/qscan](https://github.com/EthanCratchley/qscan) @8b73799) | 82 | 37 | 16 | 0 | 54 (4) | 0 | [md](results/v0.2.0/qscan-1.0.0.md) |
| cdxgen 13.6.0 (`cbom`) | 13 | 13 | 0 | 0 | 6 (0) | 0 | [md](results/v0.2.0/cdxgen-13.6.0.md) |
| Semgrep 1.183.0 + semgrep-rules @16b9e6d | 0 | 0 | 0 | 0 | 33 (0) | 5 (+6 wrong class) | [md](results/v0.2.0/semgrep-1.183.0.md) |

Semgrep is the only tool so far that scores on the defect axis: 5 hits and 6 reports of the
wrong CWE class on 162 wrong files, and 11 false alarms on the 162 fixed files planted beside
them. Its 64 rule files look for misuse, not for which public-key algorithm is in use, so the
0 on the quantum axis is expected. The other four report no misuse; they are inventory tools.

Adapter caveats (unchanged since v0.1, details in each adapter): CryptoScan's `ECC` maps to
`EC`, so its ECDSA and ECDH rows score `parent only`, and it reports no size; qscan reports
no role; cdxgen ran one fixed command, no `-t`, and its evidence step is skipped on trees
that list no package; Semgrep's family comes from `check_id` tokens.

### Tools not designed for source trees

Run on the same planted trees for completeness. Each reads a file system or image, not source
code, by its own README.

| scanner | quantum: hit / 1368 | decoys / 169 | file only (no line; not a hit) | note |
|---|---|---|---|---|
| CBOMkit-theia v1.1.2 | 1 | 0 | 0 | the hit is a PEM private key (SL-3596), plus 1 wrong family (SL-3601); does not scan source code (its README) |
| CipherIQ cbom-generator 1.9.3, default | 0 | 0 | 4 | reports 4 of the PEM key files (SL-3596–3599), without a line |
| CipherIQ cbom-generator 1.9.3, `--discover-services` | 0 | 0 | 4 | its plugins look for services at absolute system paths, not in the scanned directory |

The PEM rows carry real throwaway keys (see [Test keys](#test-keys)); with placeholder bodies
both tools reported 0 because they could not parse the key, not because they missed it.

The open-source scanners were run in throwaway containers with no network during the scan;
images, versions and invocations are recorded in each adapter and result file. Semgrep and
cdxgen were run on GitHub's runners in 12 shards
([`measure.yml`](.github/workflows/measure.yml)) and merged with `shorlist merge`; the merged
result is the one an unsharded run gives. Where a scanner's output has no role, the scorer
takes the family's intrinsic role from `families.yaml`, so `role_ok` is not evidence about
that scanner; where it has no size, `size_ok` reads "no", meaning not reported. No row ended
in `scanner_error` in any run. Not measured: IBM sonar-cryptography (needs a SonarQube
server) and CBOMkit (a service that clones a repository by URL).

**Read qrp-mcp's row with its limits.** qrp-mcp is written by the author of ShorList (see
[Conflict of interest](#conflict-of-interest)). 488 of its 1092 hits are registry rows, which
it reads from the same registries the rows cite; without them it recognises 604 of 816. Its
misses are published row by row in the result: 216 misses and 5 wrong families on the quantum
axis, 26 false alarms on decoys, and 0 on the defect axis. No reviewer outside Elkan
Electronic has checked these numbers yet.

Measurements of other scanners are welcome as pull requests to `results/`, produced by the
generator.

## Declaration axis (supplier CBOM against the listener)

This axis does not measure the closed product. It measures the tools a firm uses to check a
supplier's CBOM against what the product's listener accepts, on pairs where CycloneDX 1.7
allows exactly one reading.

- **A row** ([`generator/shorlist/declared/rows/`](generator/shorlist/declared/rows/), not
  `forms/`) is a pair: a small CycloneDX 1.7 declaration of one TLS listener (validated
  against the 1.7.2 schema) and the set that listener **accepted** when a reference client
  offered each candidate group and cipher suite alone, plus the one verdict for one category
  (`group` or `cipher_suite`): `consistent`, `undeclared` (accepted, not declared),
  `overclaimed` (declared, refused when offered alone) or `parameter_mismatch` (one declared
  and one accepted item of the same family). Items are joined on IANA code points only; every
  declared spelling carries a verbatim line of the dated IANA copy in `declared/data/`.
- **Decoys** are consistent rows whose declaration spells the wire differently: identifier
  and name spellings, a hybrid declared as a `combiner`, a group declared as an algorithm or
  as a family without a curve, and items in a `scope: excluded` component.
- **Observations** are captured, not written: the listeners
  ([`declared/listeners.yaml`](generator/shorlist/declared/listeners.yaml)) are nginx 1.30.6,
  Apache httpd 2.4.69 and `openssl s_server` 3.5.9 in the network axis's images, probed by
  [`declared/probe.py`](generator/shorlist/declared/probe.py); results are in
  `declared/observations/`, bound to the sha256 of the configuration they came from.
- **SSH** rows are listed as `not_scored: no_spec_structure`: CycloneDX has no field for SSH
  key exchange or host key algorithms ([#1162](https://github.com/CycloneDX/specification/issues/1162)).
- **Scoring**: `hit`, `miss`, `false_alarm`, `ok`, and `partial` in its own column (a
  parameter mismatch reported as two unlinked findings). A tool is given the declaration and
  an observed CBOM built from the capture in one fixed way (`declared/observed.py`).
- **Positive control**: [`declared/reference.py`](generator/shorlist/declared/reference.py),
  a plain implementation of the scope rules. It is a reference, not a scanner, and must score
  100%; that is what shows each row is decidable from the pair and the public registries.

```sh
cd generator
python -m shorlist declared --validate
docker build -t shorlist-live:1              ../containers/live        # only for --capture
docker build -t shorlist-sbom-tools:0.3.0    ../containers/sbom-tools
docker build -t shorlist-cyclonedx-cli:0.33.1 ../containers/cyclonedx-cli
python -m shorlist declared --adapter reference --adapter sbom-tools --adapter cyclonedx-cli \
    --out-dir ../results/declared
python -m shorlist declared --capture        # re-capture the listeners (docker, shorlist-live:1)
```

| tool | non-consistent pairs reproduced | partial | false alarms on consistent pairs | fingerprint |
|---|---|---|---|---|
| reference comparator (control, not a scanner) | 33 / 33 | 0 | 0 / 25 | see [`results/declared/`](results/declared/) |
| sbom-tools 0.3.0 (`diff -o json`) | 3 / 33 | 0 | 12 / 25 | see [`results/declared/`](results/declared/) |
| cyclonedx-cli 0.33.1 (`diff --component-versions`) | 3 / 33 | 0 | 12 / 25 | see [`results/declared/`](results/declared/) |

Both tools compare components, not the cipher suites and groups inside them: the 3 hits are
the rows where a whole protocol component is missing or extra (SLD-0056 to SLD-0058, added
after a first run scored 0 of 30, to check that a component-level difference is visible to
these tools at all), and the false alarms are the decoys that declare algorithm components or
an excluded component. No third-party tool we
found compares a declaration with an observation natively; the reference comparator is ours,
and it is a control, not a contender.

Found on the way: cyclonedx-cli 0.33.1, through the CycloneDX .NET library it is built on,
drops `algorithmFamily`, `ellipticCurve`, `tlsGroups` and `tlsSignatureSchemes` when it reads
and writes a 1.7 BOM, and writes absent security levels as `0`, while `validate` on the same
BOM passes. Reported as
[cyclonedx-dotnet-library#455](https://github.com/CycloneDX/cyclonedx-dotnet-library/issues/455);
a fix is proposed in
[#456](https://github.com/CycloneDX/cyclonedx-dotnet-library/pull/456), not merged at the time
of writing. The declaration adapter reads these fields from the document the tool was given,
so the scores above do not depend on the loss.

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

See [`CITATION.cff`](CITATION.cff).

> Tenev, S. *ShorList: an open catalogue of cryptographic forms*, version 0.2.0, 2026.
> Zenodo. https://doi.org/10.5281/zenodo.23974515

## Licences

- Catalogue data (`forms/`, `schema/`, `results/`): [CC BY 4.0](LICENSE-DATA).
- Generator and tests (`generator/`, `tests/`, CI): [Apache-2.0](LICENSE).
