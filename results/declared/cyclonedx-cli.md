**cyclonedx-cli 0.33.1** on the ShorList declaration axis (60 rows, rows sha256 `fd4daaf39186`, fingerprint `5841e7307c539c11`)

Of 33 non-consistent pairs on the ShorList declaration axis, cyclonedx-cli 0.33.1 reproduces 3 verdicts (0 partial); of 25 consistent pairs (20 of them decoys), it raises 12 false alarms. 2 SSH rows are not scored (no_spec_structure, CycloneDX #1162).

*By verdict class*

| verdict | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| consistent | 25 | 0 | 0 | 0 | 12 | 13 | 0 |
| overclaimed | 13 | 2 | 0 | 11 | 0 | 0 | 0 |
| parameter_mismatch | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| undeclared | 14 | 1 | 0 | 13 | 0 | 0 | 0 |

*By server*

| server | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| apache | 16 | 1 | 0 | 9 | 3 | 3 | 0 |
| nginx | 21 | 2 | 0 | 10 | 5 | 4 | 0 |
| s_server | 21 | 0 | 0 | 11 | 4 | 6 | 0 |

*By decoy class (consistent rows)*

| decoy | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| - | 5 | 0 | 0 | 0 | 0 | 5 | 0 |
| hybrid_spelling | 3 | 0 | 0 | 0 | 3 | 0 | 0 |
| identifier_spelling | 8 | 0 | 0 | 0 | 0 | 8 | 0 |
| inactive_scope | 3 | 0 | 0 | 0 | 3 | 0 | 0 |
| parent_child | 6 | 0 | 0 | 0 | 6 | 0 | 0 |

*By category*

| category | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| cipher_suite | 25 | 2 | 0 | 12 | 3 | 8 | 0 |
| group | 33 | 1 | 0 | 18 | 9 | 5 | 0 |

