**Of 20 positive forms in ShorList 0.1.0, qrp-mcp 0.44.0 recognises 20; of 10 decoys it reports 0 as a use. This measures recognition of a form in a minimal context; it is not recall and not finding in a real tree.**

catalogue 0.1.0 sha256 `7ed22c2f1943680f…` · generator 0.1.0 · fingerprint `6e0beab7f5a80f82…`

| positive forms | hit | parent only | wrong family | miss | decoys | ok | false alarm |
|---|---|---|---|---|---|---|---|
| 20 | 20 | 0 | 0 | 0 | 10 | 10 | 0 |

| form_kind | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| api_call | 6 / 6 | 0 / 2 |
| api_string | 3 / 3 | 0 / 2 |
| config_value | 5 / 5 | 0 / 5 |
| oid | 1 / 1 | 0 / 0 |
| registry_id | 5 / 5 | 0 / 1 |

| family | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| ECDSA | 6 / 6 | 0 / 3 |
| ML-KEM | 6 / 6 | 0 / 3 |
| RSA | 8 / 8 | 0 / 4 |

| language / product | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| Go / crypto/tls | 0 / 0 | 0 / 1 |
| Go / stdlib | 3 / 3 | 0 / 1 |
| IANA JOSE | 1 / 1 | 0 / 0 |
| IANA TLS | 4 / 4 | 0 / 1 |
| Java / JCA | 3 / 3 | 0 / 2 |
| Java / java.security | 0 / 0 | 0 / 1 |
| OpenSSH sshd | 3 / 3 | 0 / 2 |
| Python / any | 1 / 1 | 0 / 0 |
| Python / pyca cryptography | 3 / 3 | 0 / 1 |
| nginx | 2 / 2 | 0 / 1 |

| id | decoy | outcome | reported as use | reported as not-use | role ok | size ok |
|---|---|---|---|---|---|---|
| SL-0001 |  | hit | RSA | — | — | yes |
| SL-0002 |  | hit | ECDSA | — | yes | — |
| SL-0003 |  | hit | ML-KEM | — | yes | — |
| SL-0004 |  | hit | RSA | — | — | — |
| SL-0005 |  | hit | ECDSA | — | yes | — |
| SL-0006 |  | hit | ML-KEM | — | yes | — |
| SL-0007 |  | hit | RSA | — | — | — |
| SL-0008 |  | hit | RSA | — | — | yes |
| SL-0009 |  | hit | ECDSA | — | yes | — |
| SL-0010 |  | hit | ML-KEM | — | yes | — |
| SL-0011 |  | hit | ECDH, ML-KEM, X25519 | — | yes | — |
| SL-0012 |  | hit | RSA | — | no | — |
| SL-0013 |  | hit | RSA | — | yes | — |
| SL-0014 |  | hit | EC, ECDSA | — | yes | yes |
| SL-0015 |  | hit | ML-KEM, X25519 | — | yes | — |
| SL-0016 |  | hit | EC, ECDSA | — | yes | yes |
| SL-0017 |  | hit | RSA | — | yes | — |
| SL-0018 |  | hit | ML-KEM | — | yes | — |
| SL-0019 |  | hit | RSA | — | no | — |
| SL-0020 |  | hit | ECDSA | — | yes | yes |
| SL-0021 | yes | ok | — | — | — | — |
| SL-0022 | yes | ok | — | — | — | — |
| SL-0023 | yes | ok | — | RSA | — | — |
| SL-0024 | yes | ok | — | ECDSA | — | — |
| SL-0025 | yes | ok | — | ECDSA | — | — |
| SL-0026 | yes | ok | — | ML-KEM | — | — |
| SL-0027 | yes | ok | — | EC, ECDSA | — | — |
| SL-0028 | yes | ok | — | — | — | — |
| SL-0029 | yes | ok | — | ML-KEM, X25519 | — | — |
| SL-0030 | yes | ok | — | RSA | — | — |
