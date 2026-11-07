# ShorList

**An open catalogue of the cryptographic forms Shor's algorithm breaks — and the
post-quantum ones that replace them.**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23974515.svg)](https://doi.org/10.5281/zenodo.23974515)
[![Data: CC BY 4.0](https://img.shields.io/badge/data-CC%20BY%204.0-lightgrey.svg)](LICENSE-DATA)
[![Code: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg)](LICENSE)
[![Version 0.2.0](https://img.shields.io/badge/version-0.2.0-informational.svg)](VERSION)
[![Rows: 2004](https://img.shields.io/badge/rows-2004-success.svg)](forms/)
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
    C["ShorList v0.2.0<br/>2004 rows, a primary source on each"] --> Q["quantum<br/>1510 rows (165 decoys)<br/>Shor-vulnerable + post-quantum"]
    C --> W["weak<br/>307 rows (31 decoys)<br/>SHA-1, MD5, 3DES, RSA-1024 …"]
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
- **Filter to your stack**: run only the rows for your languages and products. *Coming before
  the v0.2.0 release.*
- **Add it to CI**: a GitHub Action that scores a scanner on every pull request. *Coming before
  the v0.2.0 release.*

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

2004 rows, every one checked against a primary source; 75 more wait in
[`candidates/`](candidates/) (no primary source yet, or no family in the vocabulary).

| axis | rows | positive | decoys | families |
|---|---|---|---|---|
| quantum | 1510 | 1345 | 165 | RSA, DSA, DH, EC, ECDSA, ECDH, EdDSA, X25519, X448, ML-KEM, ML-DSA, SLH-DSA, LMS, XMSS |
| weak | 307 | 276 | 31 | SHA-1, MD5, MD4, DES, 3DES, RC4, RC2, and weak parameters of quantum families (RSA-1024, DH-1024, P-192 …) |
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
parsing it, and a placeholder body gives them nothing to parse (v0.2.0 used the body
`VGhpcyBpcyBub3QgYSBrZXku`, "This is not a key."). The label on line 1 is still the row's
literal, so `expected` is unchanged; the key size the body happens to have (RSA-2048, DSA-2048,
P-256, 2048-bit DH) is not scored, because the label does not pin it. The commands are in
[`tools/make_test_keys.sh`](tools/make_test_keys.sh); the keys themselves are data in
`forms/`, and the private halves of the public-key rows were not kept.
**Secret scanners will flag these files.** That is expected: they are listed in
[`.github/secret_scanning.yml`](.github/secret_scanning.yml) (`paths-ignore`) and in
[`.gitleaks.toml`](.gitleaks.toml), by file, not by folder. The decoy SL-3605 is an error
message that names the label and has no body; it stays that way.

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

**These results are for v0.1 (30 rows, quantum axis only).** The v0.2 catalogue has not
been measured yet; its results will replace this section.

A 0 here means the tool reported none of these forms in this setup; it is not a judgement of the tool for its own purpose.

### Source-code scanners

| scanner | positive forms recognised | decoys reported as a use | adapter caveat | fingerprint |
|---|---|---|---|---|
| qrp-mcp 0.44.0 | 20 / 20 | 0 / 10 | see the notes below | see [`results/v0.1.1/`](results/v0.1.1/) |
| CSNP CryptoScan v1.5.0 | 8 / 20 (+ 3 parent `EC`) | 4 / 10 | CBOM output read; size n/a; role from CycloneDX `primitive` only; its names mapped as its PATTERNS.md defines them: `ECC` (ECC-001 "Elliptic Curve") -> `EC`, so the 3 ECDSA rows score `parent_only`; `Hybrid-KEM` (HYBRID-KEM-001 "X25519+ML-KEM") -> `ML-KEM` | see [`results/v0.1.1/`](results/v0.1.1/) |
| qscan 1.0.0 ([EthanCratchley/qscan](https://github.com/EthanCratchley/qscan) @8b73799) | 7 / 20 | 2 / 10 | CBOM output read; role n/a (`pke` for RSA and ECDSA alike); size from `parameterSetIdentifier`; no AI triage | see [`results/v0.1.1/`](results/v0.1.1/) |
| cdxgen 13.6.0 (`cbom`) | 0 / 20 | 0 / 10 | one fixed command, no `-t`; 0 `cryptographic-asset` components: 27 trees list no package so its evidence step is skipped, and on the 3 with a `cryptography` import its atom slicer exited with status 1 | see [`results/v0.1.1/`](results/v0.1.1/) |
| Semgrep 1.183.0 + semgrep-rules @16b9e6d | 0 / 20 | 0 / 10 | 64 rule files from directories whose path contains `crypt`; family from `check_id` tokens; 10 of 30 planted files are in no language those rules cover | see [`results/v0.1.1/`](results/v0.1.1/) |

### Tools not designed for source trees

Run on the same planted trees for completeness. Each reads a file system or image, not source
code, by its own README.

| scanner | positive forms recognised | decoys reported as a use | adapter caveat | fingerprint |
|---|---|---|---|---|
| CBOMkit-theia v1.1.2 | 0 / 20 | 0 / 10 | does not scan source code (its README); 0 components on all 30 trees | see [`results/v0.1.1/`](results/v0.1.1/) |
| CipherIQ cbom-generator 1.9.3, default | 0 / 20 | 0 / 10 | scans Linux systems for certificates, keys, algorithms and cryptographic libraries (its README); README basic invocation `--output cbom.json <dirs>`; components without a location in the planted tree are dropped (the same 9 algorithms and 6 libraries appear on an empty directory); none had one | see [`results/v0.1.1/`](results/v0.1.1/) |
| CipherIQ cbom-generator 1.9.3, `--discover-services` | 0 / 20 | 0 / 10 | README service-discovery invocation (`--discover-services --plugin-dir …/plugins/ubuntu --cyclonedx-spec=1.7`); all 60 plugins loaded; the plugins look for a service at absolute system paths (`/usr/sbin/nginx`, `/etc/nginx/nginx.conf`), not in the scanned directory, and the trees were not moved there; it found 7 checksum tools of its own container, with no location in the tree | see [`results/v0.1.1/`](results/v0.1.1/) |

The open-source scanners were run in throwaway containers with no network during the scan;
images, versions and invocations are recorded in each adapter and result file. Where a
scanner's output has no role, the scorer takes the family's intrinsic role from
`families.yaml`, so `role_ok` is not evidence about that scanner; where it has no size,
`size_ok` reads "no", meaning not reported. Not measured: IBM
sonar-cryptography (needs a SonarQube server) and CBOMkit (a service that clones a repository
by URL).

Role is wrong on 2 of the 16 rows where a role is expected: for `TLS_RSA_WITH_AES_128_GCM_SHA256`
and its OpenSSL name `AES128-GCM-SHA256`, qrp-mcp reports RSA as key establishment only;
the suite uses RSA for both key transport and authentication.

Read the 20 / 20 with its limits. The five IANA-identifier rows (SL-0016 to SL-0020) are
not independent evidence for qrp-mcp, because it builds its name tables from the same
registries. v0.1 holds only the common forms of three families. Known gaps in qrp-mcp lie
outside this slice: OIDs, NIST `P-224`/`B-*`/`K-*` curve names, and some PyCryptodome and
pyca calls. They are the next rows to add, and the score is expected to fall when they go
in. Measurements of other
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

See [`CITATION.cff`](CITATION.cff).

> Tenev, S. *ShorList: an open catalogue of cryptographic forms*, version 0.2.0, 2026.
> Zenodo. https://doi.org/10.5281/zenodo.23974515

## Licences

- Catalogue data (`forms/`, `schema/`, `results/`): [CC BY 4.0](LICENSE-DATA).
- Generator and tests (`generator/`, `tests/`, CI): [Apache-2.0](LICENSE).
