**Of 23 positive rows planted as live servers from ShorList 0.2.0, ssh-audit v3.9.0 reports the expected wire item for 22; of 7 removal/ban decoys it reports 0 as offered. Rows the reference client could not confirm on the wire are not scored.**

wire.yaml sha256 `01304235d689247f…` · catalogue 0.2.0 sha256 `e48462b539beba59…` · generator 0.1.0 · fingerprint `4f93bbce9deefd29…`

| positive rows | hit | miss | false alarm | decoys | ok | false alarm |
|---|---|---|---|---|---|---|
| 23 | 22 | 1 | 0 | 7 | 7 | 0 |

Not scored: not_runnable/config_rejected 2, not_scored/comment_decoy 2, not_scored/not_on_wire 1

| positive control | catch row | outcome | decoy row | outcome | passed |
|---|---|---|---|---|---|
| ssh | SL-0015 | hit | SL-0029 | ok | yes |

| server | hit / positive | false alarm / decoys | not scored |
|---|---|---|---|
| openssh | 22 / 23 | 0 / 7 | not_runnable/config_rejected 2, not_scored/not_on_wire 1, not_scored/comment_decoy 2 |

| family | hit / positive | false alarm / decoys | not scored |
|---|---|---|---|
| 3DES | 1 / 1 | 0 / 1 | — |
| DH | 3 / 3 | 0 / 1 | not_scored/comment_decoy 1 |
| ECDH | 1 / 1 | 0 / 1 | — |
| ECDSA | 1 / 2 | 0 / 0 | not_scored/not_on_wire 1 |
| EdDSA | 1 / 1 | 0 / 0 | — |
| MD5 | 4 / 4 | 0 / 0 | not_scored/comment_decoy 1 |
| ML-DSA | 0 / 0 | 0 / 0 | not_runnable/config_rejected 1 |
| ML-KEM | 1 / 1 | 0 / 1 | not_runnable/config_rejected 1 |
| RSA | 2 / 2 | 0 / 1 | — |
| SHA-1 | 6 / 6 | 0 / 1 | — |
| X25519 | 2 / 2 | 0 / 1 | — |

| id | server | decoy | literal | outcome | detail | reference client |
|---|---|---|---|---|---|---|
| SL-0013 | openssh |  | `HostKeyAlgorithms rsa-sha2-512` | hit | — | rsa-sha2-512 on wire |
| SL-0014 | openssh |  | `PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256` | miss | ecdsa-sha2-nistp256 | ecdsa-sha2-nistp256 on wire |
| SL-0015 | openssh |  | `KexAlgorithms mlkem768x25519-sha256` | hit | — | mlkem768x25519-sha256 on wire |
| SL-0029 | openssh | yes | `KexAlgorithms -mlkem768x25519-sha256` | ok | — | mlkem768x25519-sha256 not on wire |
| SL-0030 | openssh | yes | `HostKeyAlgorithms -ssh-rsa` | ok | — | ssh-rsa not on wire |
| SL-1172 | openssh |  | `HostKeyAlgorithms ssh-ed25519` | hit | — | ssh-ed25519 on wire |
| SL-1173 | openssh |  | `HostKeyAlgorithms ssh-mldsa44-ed25519` | not_runnable | config_rejected | — |
| SL-1174 | openssh |  | `KexAlgorithms curve25519-sha256` | hit | — | curve25519-sha256 on wire |
| SL-1175 | openssh |  | `KexAlgorithms diffie-hellman-group16-sha512` | hit | — | diffie-hellman-group16-sha512 on wire |
| SL-1176 | openssh |  | `KexAlgorithms ecdh-sha2-nistp384` | hit | — | ecdh-sha2-nistp384 on wire |
| SL-1177 | openssh |  | `KexAlgorithms mlkem768nistp256-sha256` | not_runnable | config_rejected | — |
| SL-1178 | openssh |  | `CASignatureAlgorithms ecdsa-sha2-nistp521` | not_scored | not_on_wire | — |
| SL-1189 | openssh | yes | `#KexAlgorithms diffie-hellman-group14-sha256` | not_scored | comment_decoy | — |
| SL-1190 | openssh | yes | `KexAlgorithms -ecdh-sha2-nistp256` | ok | — | ecdh-sha2-nistp256 not on wire |
| SL-4581 | openssh |  | `Ciphers 3des-cbc` | hit | — | 3des-cbc on wire |
| SL-4582 | openssh |  | `MACs hmac-md5` | hit | — | hmac-md5 on wire |
| SL-4583 | openssh |  | `MACs hmac-md5-96` | hit | — | hmac-md5-96 on wire |
| SL-4584 | openssh |  | `MACs hmac-md5-etm@openssh.com` | hit | — | hmac-md5-etm@openssh.com on wire |
| SL-4585 | openssh |  | `MACs hmac-md5-96-etm@openssh.com` | hit | — | hmac-md5-96-etm@openssh.com on wire |
| SL-4586 | openssh |  | `MACs hmac-sha1` | hit | — | hmac-sha1 on wire |
| SL-4587 | openssh |  | `MACs hmac-sha1-96` | hit | — | hmac-sha1-96 on wire |
| SL-4588 | openssh |  | `MACs hmac-sha1-etm@openssh.com` | hit | — | hmac-sha1-etm@openssh.com on wire |
| SL-4589 | openssh |  | `MACs hmac-sha1-96-etm@openssh.com` | hit | — | hmac-sha1-96-etm@openssh.com on wire |
| SL-4590 | openssh |  | `KexAlgorithms diffie-hellman-group1-sha1` | hit | — | diffie-hellman-group1-sha1 on wire |
| SL-4591 | openssh |  | `KexAlgorithms diffie-hellman-group14-sha1` | hit | — | diffie-hellman-group14-sha1 on wire |
| SL-4592 | openssh |  | `KexAlgorithms diffie-hellman-group-exchange-sha1` | hit | — | diffie-hellman-group-exchange-sha1 on wire |
| SL-4593 | openssh | yes | `Ciphers -3des-cbc` | ok | — | 3des-cbc not on wire |
| SL-4594 | openssh | yes | `MACs -hmac-sha1*` | ok | — | hmac-sha1 not on wire; hmac-sha1-96 not on wire; hmac-sha1-etm@openssh.com not on wire |
| SL-4595 | openssh | yes | `KexAlgorithms -diffie-hellman-group1-sha1` | ok | — | diffie-hellman-group1-sha1 not on wire |
| SL-4596 | openssh | yes | `#MACs hmac-md5` | not_scored | comment_decoy | — |
| SL-6523 | openssh |  | `KexAlgorithms curve25519-sha256@libssh.org` | hit | — | curve25519-sha256@libssh.org on wire |
| SL-6524 | openssh |  | `KexAlgorithms diffie-hellman-group-exchange-sha256` | hit | — | diffie-hellman-group-exchange-sha256 on wire |
| SL-6525 | openssh |  | `HostKeyAlgorithms ecdsa-sha2-nistp256` | hit | — | ecdsa-sha2-nistp256 on wire |
| SL-6526 | openssh |  | `HostKeyAlgorithms +ssh-rsa` | hit | — | ssh-rsa on wire |
| SL-6527 | openssh | yes | `KexAlgorithms -curve25519-sha256@libssh.org` | ok | — | curve25519-sha256@libssh.org not on wire |
