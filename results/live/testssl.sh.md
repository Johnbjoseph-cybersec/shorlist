**Of 14 positive rows planted as live servers from ShorList 0.2.0, testssl.sh 3.2.5 reports the expected wire item for 14; of 5 removal/ban decoys it reports 0 as offered. Rows the reference client could not confirm on the wire are not scored.**

wire.yaml sha256 `01304235d689247f…` · catalogue 0.2.0 sha256 `e48462b539beba59…` · generator 0.1.0 · fingerprint `b1b10ab05132349f…`

| positive rows | hit | miss | false alarm | decoys | ok | false alarm |
|---|---|---|---|---|---|---|
| 14 | 14 | 0 | 0 | 5 | 5 | 0 |

Not scored: not_runnable/cloud 36, not_runnable/config_rejected 13, not_runnable/not_attempted 3, not_scored/comment_decoy 3, not_scored/not_offered 2, not_scored/not_on_wire 1

| positive control | catch row | outcome | decoy row | outcome | passed |
|---|---|---|---|---|---|
| tls | SL-0011 | hit | SL-0022 | ok | yes |

| server | hit / positive | false alarm / decoys | not scored |
|---|---|---|---|
| apache | 3 / 3 | 0 / 1 | not_scored/comment_decoy 2, not_runnable/config_rejected 5, not_scored/not_offered 1 |
| nginx | 6 / 6 | 0 / 3 | not_runnable/config_rejected 8, not_scored/not_offered 1, not_scored/not_on_wire 1, not_scored/comment_decoy 1 |
| s_server | 5 / 5 | 0 / 1 | — |
| — | 0 / 0 | 0 / 0 | not_runnable/cloud 36, not_runnable/not_attempted 3 |

| family | hit / positive | false alarm / decoys | not scored |
|---|---|---|---|
| 3DES | 0 / 0 | 0 / 1 | not_runnable/config_rejected 7, not_scored/comment_decoy 1 |
| ECDH | 4 / 4 | 0 / 0 | not_scored/comment_decoy 1 |
| ECDSA | 1 / 1 | 0 / 0 | not_runnable/cloud 10 |
| EdDSA | 0 / 0 | 0 / 0 | not_runnable/cloud 2 |
| MD5 | 0 / 0 | 0 / 1 | not_scored/not_offered 1 |
| ML-KEM | 5 / 5 | 0 / 1 | not_runnable/cloud 14, not_scored/comment_decoy 1, not_runnable/not_attempted 3 |
| RC4 | 0 / 0 | 0 / 1 | not_runnable/config_rejected 6, not_scored/not_offered 1 |
| RSA | 2 / 2 | 0 / 1 | not_runnable/cloud 10 |
| TLS | 0 / 0 | 0 / 0 | not_scored/not_on_wire 1 |
| X25519 | 2 / 2 | 0 / 0 | — |

| id | server | decoy | literal | outcome | detail | reference client |
|---|---|---|---|---|---|---|
| SL-0011 | nginx |  | `ssl_ecdh_curve X25519MLKEM768;` | hit | — | X25519MLKEM768 on wire |
| SL-0012 | nginx |  | `ssl_ciphers AES128-GCM-SHA256;` | hit | — | TLS_RSA_WITH_AES_128_GCM_SHA256 on wire |
| SL-0022 | nginx | yes | `ssl_ciphers HIGH:!kRSA:!aNULL;` | ok | — | 32 not_seen suites not on wire |
| SL-1170 | apache |  | `SSLOpenSSLConfCmd Curves P-384` | hit | — | secp384r1 on wire |
| SL-1171 | apache |  | `SSLOpenSSLConfCmd Groups SecP384r1MLKEM1024` | hit | — | SecP384r1MLKEM1024 on wire |
| SL-1192 | apache | yes | `#SSLOpenSSLConfCmd Curves P-384` | not_scored | comment_decoy | — |
| SL-2060 | s_server |  | `return SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768");` | hit | — | X25519MLKEM768 on wire |
| SL-2061 | s_server |  | `return SSL_CTX_set1_groups_list(ctx, "SecP384r1MLKEM1024");` | hit | — | SecP384r1MLKEM1024 on wire |
| SL-2062 | s_server |  | `return SSL_CTX_set1_groups_list(ctx, "X25519");` | hit | — | x25519 on wire |
| SL-2063 | s_server |  | `return SSL_CTX_set1_sigalgs_list(ctx, "ecdsa_secp256r1_sha256");` | hit | — | ecdsa_secp256r1_sha256 on wire |
| SL-2064 | s_server |  | `return SSL_CTX_set1_sigalgs_list(ctx, "RSA+SHA256");` | hit | — | rsa_pkcs1_sha256 on wire |
| SL-2080 | s_server | yes | `return SSL_CTX_set1_groups_list(ctx, "DEFAULT:-X25519MLKEM768");` | ok | — | X25519MLKEM768 not on wire |
| SL-3064 | — |  | `KeyAlgorithm: RSA_2048` | not_runnable | cloud | — |
| SL-3065 | — |  | `KeyAlgorithm: EC_prime256v1` | not_runnable | cloud | — |
| SL-3066 | — |  | `KeyAlgorithm: EC_secp384r1` | not_runnable | cloud | — |
| SL-3067 | — |  | `key_algorithm     = "EC_secp384r1"` | not_runnable | cloud | — |
| SL-3068 | — |  | `key_algorithm     = "RSA_2048"` | not_runnable | cloud | — |
| SL-3069 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-3-PQ-2025-09` | not_runnable | cloud | — |
| SL-3070 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09` | not_runnable | cloud | — |
| SL-3071 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-PQ-2025-09` | not_runnable | cloud | — |
| SL-3072 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09` | not_runnable | cloud | — |
| SL-3073 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` | not_runnable | cloud | — |
| SL-3074 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09` | not_runnable | cloud | — |
| SL-3075 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09` | not_runnable | cloud | — |
| SL-3076 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09` | not_runnable | cloud | — |
| SL-3077 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09` | not_runnable | cloud | — |
| SL-3078 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09` | not_runnable | cloud | — |
| SL-3079 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09` | not_runnable | cloud | — |
| SL-3080 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-0-PQ-2025-09` | not_runnable | cloud | — |
| SL-3081 | — |  | `SslPolicy: ELBSecurityPolicy-TLS13-1-0-FIPS-PQ-2025-09` | not_runnable | cloud | — |
| SL-3082 | — |  | `ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"` | not_runnable | cloud | — |
| SL-3205 | — |  | `algorithm: RSA` | not_runnable | cloud | — |
| SL-3206 | — |  | `algorithm: ECDSA` | not_runnable | cloud | — |
| SL-3207 | — |  | `algorithm: Ed25519` | not_runnable | cloud | — |
| SL-3208 | — |  | `size: 4096` | not_runnable | cloud | — |
| SL-3209 | — |  | `size: 8192` | not_runnable | cloud | — |
| SL-3210 | — |  | `size: 384` | not_runnable | cloud | — |
| SL-3211 | — |  | `size: 521` | not_runnable | cloud | — |
| SL-3212 | — |  | `signatureAlgorithm: SHA256WithRSA` | not_runnable | cloud | — |
| SL-3213 | — |  | `signatureAlgorithm: SHA384WithRSA` | not_runnable | cloud | — |
| SL-3214 | — |  | `signatureAlgorithm: SHA512WithRSA` | not_runnable | cloud | — |
| SL-3215 | — |  | `signatureAlgorithm: ECDSAWithSHA256` | not_runnable | cloud | — |
| SL-3216 | — |  | `signatureAlgorithm: ECDSAWithSHA384` | not_runnable | cloud | — |
| SL-3217 | — |  | `signatureAlgorithm: ECDSAWithSHA512` | not_runnable | cloud | — |
| SL-3218 | — |  | `signatureAlgorithm: PureEd25519` | not_runnable | cloud | — |
| SL-3219 | — | yes | `# privateKey: {algorithm: RSA, size: 4096} until the HSM issuer supports ECDSA` | not_runnable | cloud | — |
| SL-3220 | — | yes | `note.example.com/previous-key: ECDSA P-384` | not_runnable | cloud | — |
| SL-3224 | — | yes | `# signatureAlgorithm: SHA256WithRSA` | not_runnable | cloud | — |
| SL-4562 | nginx |  | `ssl_ciphers DES-CBC3-SHA;` | not_runnable | config_rejected | — |
| SL-4563 | nginx |  | `ssl_ciphers ECDHE-RSA-DES-CBC3-SHA;` | not_runnable | config_rejected | — |
| SL-4564 | nginx |  | `ssl_ciphers ECDHE-ECDSA-DES-CBC3-SHA;` | not_runnable | config_rejected | — |
| SL-4565 | nginx |  | `ssl_ciphers DHE-RSA-DES-CBC3-SHA;` | not_runnable | config_rejected | — |
| SL-4566 | nginx |  | `ssl_ciphers RC4-SHA;` | not_runnable | config_rejected | — |
| SL-4567 | nginx |  | `ssl_ciphers RC4-MD5;` | not_runnable | config_rejected | — |
| SL-4568 | nginx |  | `ssl_ciphers ECDHE-RSA-RC4-SHA;` | not_runnable | config_rejected | — |
| SL-4569 | nginx |  | `ssl_ciphers ECDHE-ECDSA-RC4-SHA;` | not_runnable | config_rejected | — |
| SL-4570 | nginx |  | `ssl_ciphers NULL-MD5;` | not_scored | not_offered | TLS_RSA_WITH_NULL_MD5 not on wire |
| SL-4571 | apache |  | `SSLCipherSuite DES-CBC3-SHA` | not_runnable | config_rejected | — |
| SL-4572 | apache |  | `SSLCipherSuite DHE-DSS-DES-CBC3-SHA` | not_runnable | config_rejected | — |
| SL-4573 | apache |  | `SSLCipherSuite RC4-SHA` | not_runnable | config_rejected | — |
| SL-4574 | apache |  | `SSLCipherSuite RC4-MD5` | not_runnable | config_rejected | — |
| SL-4575 | apache |  | `SSLCipherSuite ECDHE-RSA-DES-CBC3-SHA` | not_runnable | config_rejected | — |
| SL-4576 | apache |  | `SSLCipherSuite RC4-SHA:AES128-SHA:HIGH:MEDIUM:!aNULL:!MD5` | not_scored | not_offered | TLS_RSA_WITH_RC4_128_SHA not on wire |
| SL-4577 | nginx | yes | `ssl_ciphers HIGH:!aNULL:!MD5;` | ok | — | 13 not_seen suites not on wire |
| SL-4578 | nginx | yes | `ssl_ciphers HIGH:!aNULL:!3DES;` | ok | — | 20 not_seen suites not on wire |
| SL-4579 | apache | yes | `SSLCipherSuite HIGH:!aNULL:!RC4` | ok | — | 18 not_seen suites not on wire |
| SL-4580 | apache | yes | `#SSLCipherSuite DES-CBC3-SHA` | not_scored | comment_decoy | — |
| SL-5545 | nginx |  | `proxy_ssl_verify off;` | not_scored | not_on_wire | — |
| SL-6500 | nginx |  | `ssl_ecdh_curve secp384r1;` | hit | — | secp384r1 on wire |
| SL-6501 | nginx |  | `ssl_ecdh_curve prime256v1;` | hit | — | secp256r1 on wire |
| SL-6502 | nginx |  | `ssl_ecdh_curve secp521r1;` | hit | — | secp521r1 on wire |
| SL-6503 | nginx |  | `ssl_ecdh_curve X25519;` | hit | — | x25519 on wire |
| SL-6504 | nginx | yes | `# ssl_ecdh_curve X25519MLKEM768;` | not_scored | comment_decoy | — |
| SL-6509 | — |  | `"curves": ["x25519mlkem768"]` | not_runnable | not_attempted | — |
| SL-6510 | — |  | `- X25519MLKEM768` | not_runnable | not_attempted | — |
| SL-6511 | — |  | `exec openvpn --config server.conf --tls-groups X25519MLKEM768` | not_runnable | not_attempted | — |
| SL-6512 | apache |  | `SSLOpenSSLConfCmd Groups X25519MLKEM768` | hit | — | X25519MLKEM768 on wire |
