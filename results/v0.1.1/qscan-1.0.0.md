**Of 20 positive forms in ShorList 0.1.1, qscan 1.0.0 recognises 7; of 10 decoys it reports 2 as a use. This measures recognition of a form in a minimal context; it is not recall and not finding in a real tree.**

catalogue 0.1.1 sha256 `c0e7e6fadeb15885…` · generator 0.1.0 · fingerprint `67f8ae250fda4930…`

| positive forms | hit | parent only | wrong family | miss | decoys | ok | false alarm |
|---|---|---|---|---|---|---|---|
| 20 | 7 | 0 | 0 | 13 | 10 | 8 | 2 |

| form_kind | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| api_call | 3 / 6 | 1 / 2 |
| api_string | 2 / 3 | 1 / 2 |
| config_value | 0 / 5 | 0 / 5 |
| oid | 1 / 1 | 0 / 0 |
| registry_id | 1 / 5 | 0 / 1 |

| family | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| ECDSA | 2 / 6 | 1 / 3 |
| ML-KEM | 0 / 6 | 0 / 3 |
| RSA | 5 / 8 | 1 / 4 |

| language / product | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| Go / crypto/tls | 0 / 0 | 0 / 1 |
| Go / stdlib | 1 / 3 | 0 / 1 |
| IANA JOSE | 0 / 1 | 0 / 0 |
| IANA TLS | 1 / 4 | 0 / 1 |
| Java / JCA | 2 / 3 | 1 / 2 |
| Java / java.security | 0 / 0 | 0 / 1 |
| OpenSSH sshd | 0 / 3 | 0 / 2 |
| Python / any | 1 / 1 | 0 / 0 |
| Python / pyca cryptography | 2 / 3 | 1 / 1 |
| nginx | 0 / 2 | 0 / 1 |

| id | decoy | outcome | reported as use | reported as not-use | role ok | size ok |
|---|---|---|---|---|---|---|
| SL-0001 |  | hit | RSA | — | — | yes |
| SL-0002 |  | hit | ECDSA | — | yes | — |
| SL-0003 |  | miss | — | — | — | — |
| SL-0004 |  | hit | RSA | — | — | — |
| SL-0005 |  | hit | ECDSA | — | yes | — |
| SL-0006 |  | miss | — | — | — | — |
| SL-0007 |  | hit | RSA | — | — | — |
| SL-0008 |  | hit | RSA | — | — | yes |
| SL-0009 |  | miss | — | — | — | — |
| SL-0010 |  | miss | — | — | — | — |
| SL-0011 |  | miss | — | — | — | — |
| SL-0012 |  | miss | — | — | — | — |
| SL-0013 |  | miss | — | — | — | — |
| SL-0014 |  | miss | — | — | — | — |
| SL-0015 |  | miss | — | — | — | — |
| SL-0016 |  | miss | — | — | — | — |
| SL-0017 |  | hit | RSA | — | no | — |
| SL-0018 |  | miss | — | — | — | — |
| SL-0019 |  | miss | — | — | — | — |
| SL-0020 |  | miss | — | — | — | — |
| SL-0021 | yes | ok | — | — | — | — |
| SL-0022 | yes | ok | — | — | — | — |
| SL-0023 | yes | false_alarm | RSA | — | — | — |
| SL-0024 | yes | false_alarm | RSA | — | — | — |
| SL-0025 | yes | ok | — | — | — | — |
| SL-0026 | yes | ok | — | — | — | — |
| SL-0027 | yes | ok | — | — | — | — |
| SL-0028 | yes | ok | — | — | — | — |
| SL-0029 | yes | ok | — | — | — | — |
| SL-0030 | yes | ok | — | — | — | — |
