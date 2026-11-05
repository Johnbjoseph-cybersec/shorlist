**Of 20 positive forms in ShorList 0.1.1, cryptoscan v1.5.0 recognises 8; of 10 decoys it reports 4 as a use. This measures recognition of a form in a minimal context; it is not recall and not finding in a real tree.**

catalogue 0.1.1 sha256 `c0e7e6fadeb15885…` · generator 0.1.0 · fingerprint `efb9a14c15c51f92…`

| positive forms | hit | parent only | wrong family | miss | decoys | ok | false alarm |
|---|---|---|---|---|---|---|---|
| 20 | 8 | 3 | 0 | 9 | 10 | 6 | 4 |

| form_kind | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| api_call | 3 / 6 | 1 / 2 |
| api_string | 2 / 3 | 1 / 2 |
| config_value | 2 / 5 | 2 / 5 |
| oid | 0 / 1 | 0 / 0 |
| registry_id | 1 / 5 | 0 / 1 |

| family | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| ECDSA | 0 / 6 | 0 / 3 |
| ML-KEM | 4 / 6 | 1 / 3 |
| RSA | 4 / 8 | 3 / 4 |

| language / product | positive: hit / n | decoys: false alarm / n |
|---|---|---|
| Go / crypto/tls | 0 / 0 | 0 / 1 |
| Go / stdlib | 2 / 3 | 0 / 1 |
| IANA JOSE | 0 / 1 | 0 / 0 |
| IANA TLS | 1 / 4 | 0 / 1 |
| Java / JCA | 2 / 3 | 1 / 2 |
| Java / java.security | 0 / 0 | 1 / 1 |
| OpenSSH sshd | 1 / 3 | 1 / 2 |
| Python / any | 0 / 1 | 0 / 0 |
| Python / pyca cryptography | 1 / 3 | 1 / 1 |
| nginx | 1 / 2 | 0 / 1 |

| id | decoy | outcome | reported as use | reported as not-use | role ok | size ok |
|---|---|---|---|---|---|---|
| SL-0001 |  | hit | RSA | — | — | no |
| SL-0002 |  | parent_only | EC | — | — | — |
| SL-0003 |  | miss | — | — | — | — |
| SL-0004 |  | hit | RSA | — | — | — |
| SL-0005 |  | miss | — | — | — | — |
| SL-0006 |  | hit | ML-KEM | — | yes | — |
| SL-0007 |  | miss | — | — | — | — |
| SL-0008 |  | hit | RSA | — | — | no |
| SL-0009 |  | parent_only | EC | — | — | — |
| SL-0010 |  | hit | ML-KEM | — | yes | — |
| SL-0011 |  | hit | ML-KEM | — | yes | — |
| SL-0012 |  | miss | — | — | — | — |
| SL-0013 |  | hit | RSA | — | no | — |
| SL-0014 |  | parent_only | EC | — | — | — |
| SL-0015 |  | miss | — | — | — | — |
| SL-0016 |  | miss | — | — | — | — |
| SL-0017 |  | miss | — | — | — | — |
| SL-0018 |  | hit | ML-KEM | — | yes | — |
| SL-0019 |  | miss | — | — | — | — |
| SL-0020 |  | miss | — | — | — | — |
| SL-0021 | yes | false_alarm | RSA | — | — | — |
| SL-0022 | yes | ok | — | — | — | — |
| SL-0023 | yes | false_alarm | RSA | — | — | — |
| SL-0024 | yes | ok | — | — | — | — |
| SL-0025 | yes | ok | — | — | — | — |
| SL-0026 | yes | false_alarm | ML-KEM | — | — | — |
| SL-0027 | yes | ok | — | — | — | — |
| SL-0028 | yes | ok | — | — | — | — |
| SL-0029 | yes | ok | — | — | — | — |
| SL-0030 | yes | false_alarm | RSA | — | — | — |
