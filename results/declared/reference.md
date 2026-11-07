**shorlist reference comparator 0.1.0** on the ShorList declaration axis (60 rows, rows sha256 `fd4daaf39186`, fingerprint `d8bf8920bf564825`)

Of 33 non-consistent pairs on the ShorList declaration axis, shorlist reference comparator 0.1.0 (reference comparator: positive control, not a scanner) reproduces 33 verdicts (0 partial); of 25 consistent pairs (20 of them decoys), it raises 0 false alarms. 2 SSH rows are not scored (no_spec_structure, CycloneDX #1162).

*By verdict class*

| verdict | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| consistent | 25 | 0 | 0 | 0 | 0 | 25 | 0 |
| overclaimed | 13 | 13 | 0 | 0 | 0 | 0 | 0 |
| parameter_mismatch | 6 | 6 | 0 | 0 | 0 | 0 | 0 |
| undeclared | 14 | 14 | 0 | 0 | 0 | 0 | 0 |

*By server*

| server | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| apache | 16 | 10 | 0 | 0 | 0 | 6 | 0 |
| nginx | 21 | 12 | 0 | 0 | 0 | 9 | 0 |
| s_server | 21 | 11 | 0 | 0 | 0 | 10 | 0 |

*By decoy class (consistent rows)*

| decoy | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| - | 5 | 0 | 0 | 0 | 0 | 5 | 0 |
| hybrid_spelling | 3 | 0 | 0 | 0 | 0 | 3 | 0 |
| identifier_spelling | 8 | 0 | 0 | 0 | 0 | 8 | 0 |
| inactive_scope | 3 | 0 | 0 | 0 | 0 | 3 | 0 |
| parent_child | 6 | 0 | 0 | 0 | 0 | 6 | 0 |

*By category*

| category | n | hit | partial | miss | false_alarm | ok | tool_error |
|---|---:|---:|---:|---:|---:|---:|---:|
| cipher_suite | 25 | 14 | 0 | 0 | 0 | 11 | 0 |
| group | 33 | 19 | 0 | 0 | 0 | 14 | 0 |

*Controls*: positive control PASSED: the reference comparator must score 33/33 hits and 25/25 ok

