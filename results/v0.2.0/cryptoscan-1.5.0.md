**Of 1368 positive forms in ShorList 0.2.0, cryptoscan v1.5.0 recognises 257; of 169 decoys it reports 45 as a use. This measures recognition of a form in a minimal context; it is not recall and not finding in a real tree.**

catalogue 0.2.0 sha256 `5d0e18007d740318…` · generator 0.1.0 · fingerprint `f7d39dc36285fb4d…`

| positive forms | hit | parent only | wrong family | file only (no line; not a hit) | miss | decoys | ok | false alarm |
|---|---|---|---|---|---|---|---|---|
| 1368 | 257 | 127 | 2 | 0 | 982 | 169 | 124 | 45 |

| form_kind | positive: hit / n | file only | decoys: false alarm / n |
|---|---|---|---|
| api_call | 44 / 287 | 0 | 4 / 25 |
| api_string | 50 / 129 | 0 | 7 / 23 |
| cli | 45 / 96 | 0 | 6 / 13 |
| config_key | 0 / 5 | 0 | 0 / 4 |
| config_value | 40 / 164 | 0 | 18 / 32 |
| curve_name | 5 / 47 | 0 | 0 / 4 |
| file_format | 12 / 29 | 0 | 2 / 3 |
| oid | 2 / 59 | 0 | 1 / 3 |
| registry_id | 59 / 552 | 0 | 7 / 62 |

| family | positive: hit / n | file only | decoys: false alarm / n |
|---|---|---|---|
| DH | 13 / 190 | 0 | 3 / 26 |
| DSA | 5 / 40 | 0 | 2 / 10 |
| EC | 36 / 135 | 0 | 2 / 15 |
| ECDH | 0 / 208 | 0 | 5 / 25 |
| ECDSA | 0 / 140 | 0 | 4 / 18 |
| EdDSA | 0 / 86 | 0 | 1 / 5 |
| LMS | 4 / 10 | 0 | 0 / 0 |
| ML-DSA | 50 / 79 | 0 | 2 / 5 |
| ML-KEM | 54 / 108 | 0 | 5 / 11 |
| RSA | 85 / 256 | 0 | 19 / 49 |
| SLH-DSA | 8 / 32 | 0 | 0 / 1 |
| X25519 | 0 / 55 | 0 | 2 / 4 |
| X448 | 0 / 20 | 0 | 0 / 0 |
| XMSS | 2 / 9 | 0 | 0 / 0 |

| language / product | positive: hit / n | file only | decoys: false alarm / n |
|---|---|---|---|
| AWS CLI 2.39 / kms create-key | 3 / 7 | 0 | 1 / 1 |
| AWS CloudFormation / AWS::CertificateManager::Certificate | 1 / 3 | 0 | 0 / 0 |
| AWS CloudFormation / AWS::ElasticLoadBalancingV2::Listener | 0 / 13 | 0 | 0 / 0 |
| AWS CloudFormation / AWS::KMS::Key | 9 / 15 | 0 | 1 / 2 |
| AWS IAM policy / kms condition keys | 0 / 0 | 0 | 1 / 3 |
| Apache httpd mod_ssl | 1 / 3 | 0 | 1 / 1 |
| Azure CLI / az keyvault key create | 5 / 6 | 0 | 1 / 1 |
| Azure Key Vault REST 2025-07-01 | 5 / 16 | 0 | 1 / 1 |
| C / BoringSSL | 0 / 9 | 0 | 0 / 1 |
| C / Mbed TLS 3.6 | 1 / 22 | 0 | 0 / 3 |
| C / OpenSSL 3.5 | 9 / 37 | 0 | 2 / 4 |
| C / PKCS #11 3.2 (OASIS) | 0 / 53 | 0 | 0 / 4 |
| C / any | 0 / 4 | 0 | 0 / 0 |
| C / liboqs 0.16 | 1 / 7 | 0 | 0 / 1 |
| C / libsodium 1.0.22 | 0 / 10 | 0 | 0 / 1 |
| C / wolfSSL 5.9 | 1 / 16 | 0 | 0 / 2 |
| C# / .NET System.Security.Cryptography | 4 / 7 | 0 | 1 / 1 |
| C++ / Botan 3.14 | 5 / 14 | 0 | 0 / 1 |
| C++ / Crypto++ 8.9 | 2 / 11 | 0 | 0 / 1 |
| CLI / model_signing (sigstore/model-transparency) | 0 / 6 | 0 | 1 / 1 |
| Caddy 2.10 (JSON config) | 1 / 1 | 0 | 0 / 0 |
| Fortinet FortiOS | 1 / 3 | 0 | 0 / 0 |
| Go / cloudflare/circl | 1 / 1 | 0 | 0 / 0 |
| Go / crypto/tls | 0 / 0 | 0 | 0 / 1 |
| Go / crypto/tls 1.24 | 1 / 1 | 0 | 0 / 1 |
| Go / encoding/asn1 | 0 / 2 | 0 | 0 / 0 |
| Go / liboqs-go | 1 / 1 | 0 | 0 / 0 |
| Go / stdlib | 3 / 7 | 0 | 0 / 1 |
| Google Cloud KMS REST v1 | 0 / 2 | 0 | 0 / 1 |
| HashiCorp Vault v2.x / pki | 4 / 9 | 0 | 1 / 1 |
| HashiCorp Vault v2.x / ssh | 1 / 6 | 0 | 0 / 0 |
| HashiCorp Vault v2.x / transit | 8 / 13 | 0 | 0 / 1 |
| IANA COSE | 9 / 53 | 0 | 1 / 7 |
| IANA IKEv2 | 4 / 30 | 0 | 1 / 4 |
| IANA JOSE | 11 / 50 | 0 | 1 / 6 |
| IANA SSH | 28 / 46 | 0 | 4 / 6 |
| IANA TLS | 7 / 373 | 0 | 0 / 39 |
| JOSE JWK (RFC 7517) | 6 / 10 | 0 | 0 / 0 |
| Java / Bouncy Castle (JCA) | 2 / 2 | 0 | 0 / 0 |
| Java / Bouncy Castle JSSE 1.86 | 2 / 2 | 0 | 0 / 0 |
| Java / JCA | 2 / 5 | 0 | 1 / 3 |
| Java / JCA (JDK 24) | 3 / 3 | 0 | 0 / 1 |
| Java / JSSE (JDK 21) | 0 / 4 | 0 | 0 / 0 |
| Java / java.security | 0 / 0 | 0 | 1 / 2 |
| Java / java.security (JDK 24) | 0 / 0 | 0 | 3 / 4 |
| Java / keytool (JDK 24) | 7 / 17 | 0 | 1 / 2 |
| JavaScript / Node.js crypto | 5 / 10 | 0 | 0 / 1 |
| JavaScript / Node.js tls | 1 / 1 | 0 | 0 / 1 |
| JavaScript / Web Crypto API | 6 / 15 | 0 | 1 / 3 |
| Juniper Junos OS | 1 / 3 | 0 | 0 / 0 |
| Kotlin / Android JCA | 2 / 3 | 0 | 0 / 0 |
| Kotlin / Android Keystore | 0 / 10 | 0 | 0 / 2 |
| OMS bundle (pre-v1.1.0, model_signing <= 1.0.x) | 0 / 3 | 0 | 0 / 0 |
| OpenSC pkcs11-tool 0.26.1 | 3 / 3 | 0 | 1 / 2 |
| OpenSSH 10.2 authorized_keys | 1 / 7 | 0 | 1 / 1 |
| OpenSSH 10.2 known_hosts | 0 / 2 | 0 | 1 / 1 |
| OpenSSH 10.2 ssh-keygen | 1 / 6 | 0 | 0 / 1 |
| OpenSSH sshd | 5 / 14 | 0 | 4 / 5 |
| OpenSSL 3.5 ASN1_generate_nconf config | 3 / 8 | 0 | 1 / 1 |
| OpenSSL CLI | 4 / 10 | 0 | 0 / 2 |
| OpenVPN 2.6 (OpenSSL 3.5) | 1 / 1 | 0 | 0 / 0 |
| PEM / OpenSSL 3.5 | 5 / 10 | 0 | 0 / 1 |
| PHP / ext/openssl | 2 / 9 | 0 | 0 / 1 |
| PHP / ext/sodium | 0 / 6 | 0 | 0 / 1 |
| PHP / phpseclib 3.0 | 4 / 7 | 0 | 0 / 1 |
| Python / Boto3 1.43 (acm) | 1 / 3 | 0 | 0 / 0 |
| Python / Boto3 1.43 (kms) | 3 / 19 | 0 | 0 / 1 |
| Python / PyCryptodome | 2 / 11 | 0 | 0 / 1 |
| Python / any | 3 / 88 | 0 | 0 / 5 |
| Python / liboqs-python | 2 / 2 | 0 | 0 / 0 |
| Python / logging | 0 / 0 | 0 | 1 / 1 |
| Python / model_signing (sigstore/model-transparency) | 0 / 6 | 0 | 0 / 1 |
| Python / pyca cryptography | 1 / 5 | 0 | 1 / 1 |
| Python / ssl | 1 / 7 | 0 | 1 / 2 |
| Ruby / RbNaCl 7.1 | 0 / 2 | 0 | 0 / 0 |
| Ruby / openssl | 5 / 15 | 0 | 0 / 3 |
| Rust / RustCrypto dsa 0.7 | 0 / 1 | 0 | 0 / 0 |
| Rust / RustCrypto k256 0.14 | 0 / 1 | 0 | 0 / 0 |
| Rust / RustCrypto ml-dsa 0.1 | 1 / 1 | 0 | 0 / 0 |
| Rust / RustCrypto ml-kem 0.3 | 1 / 1 | 0 | 0 / 0 |
| Rust / RustCrypto p256 0.14 | 0 / 2 | 0 | 0 / 0 |
| Rust / RustCrypto p384 0.14 | 0 / 1 | 0 | 0 / 0 |
| Rust / RustCrypto rsa 0.9 | 5 / 5 | 0 | 0 / 1 |
| Rust / RustCrypto slh-dsa 0.1 | 1 / 1 | 0 | 0 / 0 |
| Rust / aws-lc-rs 1.19 | 4 / 11 | 0 | 0 / 0 |
| Rust / ed25519-dalek 3 | 0 / 1 | 0 | 0 / 0 |
| Rust / ring 0.17 | 1 / 10 | 0 | 0 / 1 |
| Rust / rustls 0.23 | 3 / 11 | 0 | 1 / 3 |
| Rust / x25519-dalek 3 | 0 / 3 | 0 | 0 / 0 |
| Sigstore trusted root JSON | 1 / 8 | 0 | 0 / 0 |
| Swift / Apple CryptoKit | 4 / 15 | 0 | 1 / 2 |
| Swift / Apple Security framework | 0 / 6 | 0 | 0 / 0 |
| Terraform / hashicorp/aws 6.72 | 7 / 14 | 0 | 2 / 2 |
| Terraform / hashicorp/azurerm 5.13 | 5 / 8 | 0 | 1 / 1 |
| Terraform / hashicorp/google 8.10 | 2 / 35 | 0 | 1 / 2 |
| Terraform / hashicorp/tls 4.4 | 1 / 9 | 0 | 1 / 1 |
| Traefik v3 (dynamic YAML) | 1 / 1 | 0 | 0 / 0 |
| YAML (model-signing pipeline policy) | 0 / 0 | 0 | 0 / 1 |
| cert-manager 1.21 / Certificate | 1 / 14 | 0 | 1 / 3 |
| gcloud CLI / kms keys create | 6 / 11 | 0 | 0 / 1 |
| nginx | 1 / 6 | 0 | 1 / 2 |
| strongSwan swanctl | 1 / 6 | 0 | 0 / 1 |

**weak axis** (scored apart; not in the figures above)

| positive | hit | parent_only | wrong_family | file_only | miss | decoys | ok | false alarm |
|---|---|---|---|---|---|---|---|---|
| 280 | 123 | 3 | 13 | 0 | 141 | 31 | 17 | 14 |

**defect axis** (scored apart; not in the figures above)

| positive | hit | wrong_class | miss | decoys | ok | false alarm | fixed files | false alarm |
|---|---|---|---|---|---|---|---|---|
| 162 | 0 | 0 | 162 | 25 | 25 | 0 | 162 | 0 |

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
| SL-0100 |  | miss | — | — | — | — |
| SL-0101 |  | miss | — | — | — | — |
| SL-0102 |  | miss | — | — | — | — |
| SL-0103 |  | miss | — | — | — | — |
| SL-0104 |  | miss | — | — | — | — |
| SL-0105 |  | miss | — | — | — | — |
| SL-0106 |  | miss | — | — | — | — |
| SL-0107 |  | miss | — | — | — | — |
| SL-0108 |  | miss | — | — | — | — |
| SL-0109 |  | miss | — | — | — | — |
| SL-0110 |  | miss | — | — | — | — |
| SL-0111 |  | miss | — | — | — | — |
| SL-0112 |  | parent_only | EC | — | — | — |
| SL-0113 |  | miss | — | — | — | — |
| SL-0114 |  | miss | — | — | — | — |
| SL-0115 |  | miss | — | — | — | — |
| SL-0116 |  | miss | — | — | — | — |
| SL-0117 |  | miss | — | — | — | — |
| SL-0118 |  | miss | — | — | — | — |
| SL-0119 |  | miss | — | — | — | — |
| SL-0120 |  | hit | ML-DSA | — | yes | — |
| SL-0121 |  | hit | ML-DSA | — | yes | — |
| SL-0122 |  | hit | ML-DSA | — | yes | — |
| SL-0123 |  | miss | — | — | — | — |
| SL-0124 |  | miss | — | — | — | — |
| SL-0125 |  | miss | — | — | — | — |
| SL-0126 |  | miss | — | — | — | — |
| SL-0127 |  | miss | — | — | — | — |
| SL-0128 |  | miss | — | — | — | — |
| SL-0129 |  | miss | — | — | — | — |
| SL-0130 |  | miss | — | — | — | — |
| SL-0131 |  | miss | — | — | — | — |
| SL-0132 |  | miss | — | — | — | — |
| SL-0133 |  | miss | — | — | — | — |
| SL-0134 |  | miss | — | — | — | — |
| SL-0135 | yes | ok | — | — | — | — |
| SL-0136 | yes | ok | — | — | — | — |
| SL-0137 | yes | ok | — | — | — | — |
| SL-0138 | yes | ok | — | — | — | — |
| SL-0139 |  | miss | — | — | — | — |
| SL-0140 |  | miss | — | — | — | — |
| SL-0141 |  | miss | — | — | — | — |
| SL-0142 |  | miss | — | — | — | — |
| SL-0143 |  | miss | — | — | — | — |
| SL-0144 |  | miss | — | — | — | — |
| SL-0145 |  | miss | — | — | — | — |
| SL-0146 |  | miss | — | — | — | — |
| SL-0147 |  | miss | — | — | — | — |
| SL-0148 |  | miss | — | — | — | — |
| SL-0149 |  | miss | — | — | — | — |
| SL-0150 |  | miss | — | — | — | — |
| SL-0151 |  | miss | — | — | — | — |
| SL-0152 |  | miss | — | — | — | — |
| SL-0153 |  | miss | — | — | — | — |
| SL-0154 |  | miss | — | — | — | — |
| SL-0155 |  | miss | — | — | — | — |
| SL-0156 |  | miss | — | — | — | — |
| SL-0157 |  | miss | — | — | — | — |
| SL-0158 |  | miss | — | — | — | — |
| SL-0159 |  | miss | — | — | — | — |
| SL-0160 |  | miss | — | — | — | — |
| SL-0161 |  | parent_only | EC | — | — | — |
| SL-0162 |  | parent_only | EC | — | — | — |
| SL-0163 |  | parent_only | EC | — | — | — |
| SL-0164 |  | miss | — | — | — | — |
| SL-0165 |  | miss | — | — | — | — |
| SL-0166 |  | miss | — | — | — | — |
| SL-0167 |  | miss | — | — | — | — |
| SL-0168 |  | miss | — | — | — | — |
| SL-0169 |  | miss | — | — | — | — |
| SL-0170 |  | miss | — | — | — | — |
| SL-0171 |  | miss | — | — | — | — |
| SL-0172 |  | miss | — | — | — | — |
| SL-0173 |  | miss | — | — | — | — |
| SL-0174 |  | miss | — | — | — | — |
| SL-0175 |  | miss | — | — | — | — |
| SL-0176 |  | miss | — | — | — | — |
| SL-0177 |  | hit | ML-KEM | — | yes | — |
| SL-0178 |  | hit | ML-KEM | — | yes | — |
| SL-0179 |  | miss | — | — | — | — |
| SL-0180 |  | miss | — | — | — | — |
| SL-0181 |  | miss | — | — | — | — |
| SL-0182 |  | hit | ML-KEM | — | yes | — |
| SL-0183 |  | miss | — | — | — | — |
| SL-0184 |  | miss | — | — | — | — |
| SL-0185 |  | miss | — | — | — | — |
| SL-0186 |  | miss | — | — | — | — |
| SL-0187 |  | miss | — | — | — | — |
| SL-0188 | yes | ok | — | — | — | — |
| SL-0189 | yes | ok | — | — | — | — |
| SL-0190 | yes | ok | — | — | — | — |
| SL-0191 | yes | ok | — | — | — | — |
| SL-0192 | yes | ok | — | — | — | — |
| SL-0193 |  | miss | — | — | — | — |
| SL-0194 |  | miss | — | — | — | — |
| SL-0195 |  | miss | — | — | — | — |
| SL-0196 |  | miss | — | — | — | — |
| SL-0197 |  | miss | — | — | — | — |
| SL-0198 |  | miss | — | — | — | — |
| SL-0199 |  | miss | — | — | — | — |
| SL-0200 |  | miss | — | — | — | — |
| SL-0201 |  | miss | — | — | — | — |
| SL-0202 |  | miss | — | — | — | — |
| SL-0203 |  | miss | — | — | — | — |
| SL-0204 |  | miss | — | — | — | — |
| SL-0205 |  | miss | — | — | — | — |
| SL-0206 |  | miss | — | — | — | — |
| SL-0207 |  | miss | — | — | — | — |
| SL-0208 |  | miss | — | — | — | — |
| SL-0209 |  | miss | — | — | — | — |
| SL-0210 |  | miss | — | — | — | — |
| SL-0211 |  | miss | — | — | — | — |
| SL-0212 |  | miss | — | — | — | — |
| SL-0213 |  | miss | — | — | — | — |
| SL-0214 |  | miss | — | — | — | — |
| SL-0215 |  | miss | — | — | — | — |
| SL-0216 |  | miss | — | — | — | — |
| SL-0217 |  | miss | — | — | — | — |
| SL-0218 |  | miss | — | — | — | — |
| SL-0219 |  | miss | — | — | — | — |
| SL-0220 |  | miss | — | — | — | — |
| SL-0221 |  | miss | — | — | — | — |
| SL-0222 |  | miss | — | — | — | — |
| SL-0223 |  | miss | — | — | — | — |
| SL-0224 |  | miss | — | — | — | — |
| SL-0225 |  | miss | — | — | — | — |
| SL-0226 |  | miss | — | — | — | — |
| SL-0227 |  | miss | — | — | — | — |
| SL-0228 |  | miss | — | — | — | — |
| SL-0229 |  | miss | — | — | — | — |
| SL-0230 |  | miss | — | — | — | — |
| SL-0231 |  | miss | — | — | — | — |
| SL-0232 |  | miss | — | — | — | — |
| SL-0233 |  | miss | — | — | — | — |
| SL-0234 |  | miss | — | — | — | — |
| SL-0235 |  | miss | — | — | — | — |
| SL-0236 |  | miss | — | — | — | — |
| SL-0237 |  | miss | — | — | — | — |
| SL-0238 |  | miss | — | — | — | — |
| SL-0239 |  | miss | — | — | — | — |
| SL-0240 |  | miss | — | — | — | — |
| SL-0241 |  | miss | — | — | — | — |
| SL-0242 |  | miss | — | — | — | — |
| SL-0243 |  | miss | — | — | — | — |
| SL-0244 |  | miss | — | — | — | — |
| SL-0245 |  | miss | — | — | — | — |
| SL-0246 |  | miss | — | — | — | — |
| SL-0247 |  | miss | — | — | — | — |
| SL-0248 |  | miss | — | — | — | — |
| SL-0249 |  | miss | — | — | — | — |
| SL-0250 |  | miss | — | — | — | — |
| SL-0251 |  | miss | — | — | — | — |
| SL-0252 |  | miss | — | — | — | — |
| SL-0253 |  | miss | — | — | — | — |
| SL-0254 |  | miss | — | — | — | — |
| SL-0255 |  | miss | — | — | — | — |
| SL-0256 |  | miss | — | — | — | — |
| SL-0257 |  | miss | — | — | — | — |
| SL-0258 |  | miss | — | — | — | — |
| SL-0259 |  | miss | — | — | — | — |
| SL-0260 |  | miss | — | — | — | — |
| SL-0261 |  | miss | — | — | — | — |
| SL-0262 |  | miss | — | — | — | — |
| SL-0263 |  | miss | — | — | — | — |
| SL-0264 |  | miss | — | — | — | — |
| SL-0265 |  | miss | — | — | — | — |
| SL-0266 |  | miss | — | — | — | — |
| SL-0267 |  | miss | — | — | — | — |
| SL-0268 |  | miss | — | — | — | — |
| SL-0269 |  | miss | — | — | — | — |
| SL-0270 |  | miss | — | — | — | — |
| SL-0271 |  | miss | — | — | — | — |
| SL-0272 |  | miss | — | — | — | — |
| SL-0273 |  | miss | — | — | — | — |
| SL-0274 |  | miss | — | — | — | — |
| SL-0275 |  | miss | — | — | — | — |
| SL-0276 |  | miss | — | — | — | — |
| SL-0277 |  | miss | — | — | — | — |
| SL-0278 |  | miss | — | — | — | — |
| SL-0279 |  | miss | — | — | — | — |
| SL-0280 |  | miss | — | — | — | — |
| SL-0281 |  | miss | — | — | — | — |
| SL-0282 |  | miss | — | — | — | — |
| SL-0283 |  | miss | — | — | — | — |
| SL-0284 |  | miss | — | — | — | — |
| SL-0285 |  | miss | — | — | — | — |
| SL-0286 |  | miss | — | — | — | — |
| SL-0287 |  | miss | — | — | — | — |
| SL-0288 |  | miss | — | — | — | — |
| SL-0289 |  | miss | — | — | — | — |
| SL-0290 |  | miss | — | — | — | — |
| SL-0291 |  | miss | — | — | — | — |
| SL-0292 |  | miss | — | — | — | — |
| SL-0293 |  | miss | — | — | — | — |
| SL-0294 |  | miss | — | — | — | — |
| SL-0295 |  | miss | — | — | — | — |
| SL-0296 |  | miss | — | — | — | — |
| SL-0297 |  | miss | — | — | — | — |
| SL-0298 |  | miss | — | — | — | — |
| SL-0299 |  | miss | — | — | — | — |
| SL-0300 |  | miss | — | — | — | — |
| SL-0301 |  | miss | — | — | — | — |
| SL-0302 |  | miss | — | — | — | — |
| SL-0303 |  | miss | — | — | — | — |
| SL-0304 |  | miss | — | — | — | — |
| SL-0305 |  | miss | — | — | — | — |
| SL-0306 |  | miss | — | — | — | — |
| SL-0307 |  | miss | — | — | — | — |
| SL-0308 |  | miss | — | — | — | — |
| SL-0309 |  | miss | — | — | — | — |
| SL-0310 |  | miss | — | — | — | — |
| SL-0311 |  | miss | — | — | — | — |
| SL-0312 |  | miss | — | — | — | — |
| SL-0313 |  | miss | — | — | — | — |
| SL-0314 |  | miss | — | — | — | — |
| SL-0315 |  | miss | — | — | — | — |
| SL-0316 |  | miss | — | — | — | — |
| SL-0317 |  | miss | — | — | — | — |
| SL-0318 |  | miss | — | — | — | — |
| SL-0319 |  | miss | — | — | — | — |
| SL-0320 |  | miss | — | — | — | — |
| SL-0321 |  | miss | — | — | — | — |
| SL-0322 |  | miss | — | — | — | — |
| SL-0323 |  | miss | — | — | — | — |
| SL-0324 |  | miss | — | — | — | — |
| SL-0325 |  | miss | — | — | — | — |
| SL-0326 |  | miss | — | — | — | — |
| SL-0327 |  | miss | — | — | — | — |
| SL-0328 |  | miss | — | — | — | — |
| SL-0329 |  | miss | — | — | — | — |
| SL-0330 |  | miss | — | — | — | — |
| SL-0331 |  | miss | — | — | — | — |
| SL-0332 |  | miss | — | — | — | — |
| SL-0333 |  | miss | — | — | — | — |
| SL-0334 |  | miss | — | — | — | — |
| SL-0335 |  | miss | — | — | — | — |
| SL-0336 |  | miss | — | — | — | — |
| SL-0337 |  | miss | — | — | — | — |
| SL-0338 |  | miss | — | — | — | — |
| SL-0339 |  | miss | — | — | — | — |
| SL-0340 |  | miss | — | — | — | — |
| SL-0341 |  | miss | — | — | — | — |
| SL-0342 |  | miss | — | — | — | — |
| SL-0343 |  | miss | — | — | — | — |
| SL-0344 |  | miss | — | — | — | — |
| SL-0345 |  | miss | — | — | — | — |
| SL-0346 |  | miss | — | — | — | — |
| SL-0347 |  | miss | — | — | — | — |
| SL-0348 |  | miss | — | — | — | — |
| SL-0349 |  | miss | — | — | — | — |
| SL-0350 |  | miss | — | — | — | — |
| SL-0351 |  | miss | — | — | — | — |
| SL-0352 |  | miss | — | — | — | — |
| SL-0353 |  | miss | — | — | — | — |
| SL-0354 |  | miss | — | — | — | — |
| SL-0355 |  | miss | — | — | — | — |
| SL-0356 |  | miss | — | — | — | — |
| SL-0357 |  | miss | — | — | — | — |
| SL-0358 |  | miss | — | — | — | — |
| SL-0359 |  | miss | — | — | — | — |
| SL-0360 |  | miss | — | — | — | — |
| SL-0361 |  | miss | — | — | — | — |
| SL-0362 |  | miss | — | — | — | — |
| SL-0363 |  | miss | — | — | — | — |
| SL-0364 |  | miss | — | — | — | — |
| SL-0365 |  | miss | — | — | — | — |
| SL-0366 |  | miss | — | — | — | — |
| SL-0367 |  | miss | — | — | — | — |
| SL-0368 |  | miss | — | — | — | — |
| SL-0369 |  | miss | — | — | — | — |
| SL-0370 |  | miss | — | — | — | — |
| SL-0371 |  | miss | — | — | — | — |
| SL-0372 |  | miss | — | — | — | — |
| SL-0373 |  | miss | — | — | — | — |
| SL-0374 |  | miss | — | — | — | — |
| SL-0375 |  | miss | — | — | — | — |
| SL-0376 |  | miss | — | — | — | — |
| SL-0377 |  | miss | — | — | — | — |
| SL-0378 |  | miss | — | — | — | — |
| SL-0379 |  | miss | — | — | — | — |
| SL-0380 |  | miss | — | — | — | — |
| SL-0381 |  | miss | — | — | — | — |
| SL-0382 |  | miss | — | — | — | — |
| SL-0383 |  | miss | — | — | — | — |
| SL-0384 |  | miss | — | — | — | — |
| SL-0385 |  | miss | — | — | — | — |
| SL-0386 |  | miss | — | — | — | — |
| SL-0387 |  | miss | — | — | — | — |
| SL-0388 |  | miss | — | — | — | — |
| SL-0389 |  | miss | — | — | — | — |
| SL-0390 |  | miss | — | — | — | — |
| SL-0391 |  | miss | — | — | — | — |
| SL-0392 |  | miss | — | — | — | — |
| SL-0393 |  | miss | — | — | — | — |
| SL-0394 |  | miss | — | — | — | — |
| SL-0395 |  | miss | — | — | — | — |
| SL-0396 |  | miss | — | — | — | — |
| SL-0397 |  | miss | — | — | — | — |
| SL-0398 |  | miss | — | — | — | — |
| SL-0399 |  | miss | — | — | — | — |
| SL-0400 |  | miss | — | — | — | — |
| SL-0401 |  | miss | — | — | — | — |
| SL-0402 |  | miss | — | — | — | — |
| SL-0403 |  | miss | — | — | — | — |
| SL-0404 |  | miss | — | — | — | — |
| SL-0405 |  | miss | — | — | — | — |
| SL-0406 |  | miss | — | — | — | — |
| SL-0407 |  | miss | — | — | — | — |
| SL-0408 |  | miss | — | — | — | — |
| SL-0409 |  | miss | — | — | — | — |
| SL-0410 |  | miss | — | — | — | — |
| SL-0411 |  | miss | — | — | — | — |
| SL-0412 |  | miss | — | — | — | — |
| SL-0413 |  | miss | — | — | — | — |
| SL-0414 |  | miss | — | — | — | — |
| SL-0415 |  | miss | — | — | — | — |
| SL-0416 |  | miss | — | — | — | — |
| SL-0417 |  | miss | — | — | — | — |
| SL-0418 |  | miss | — | — | — | — |
| SL-0419 |  | miss | — | — | — | — |
| SL-0420 |  | miss | — | — | — | — |
| SL-0421 |  | miss | — | — | — | — |
| SL-0422 |  | miss | — | — | — | — |
| SL-0423 |  | miss | — | — | — | — |
| SL-0424 |  | miss | — | — | — | — |
| SL-0425 |  | miss | — | — | — | — |
| SL-0426 |  | miss | — | — | — | — |
| SL-0427 |  | miss | — | — | — | — |
| SL-0428 |  | miss | — | — | — | — |
| SL-0429 |  | miss | — | — | — | — |
| SL-0430 |  | miss | — | — | — | — |
| SL-0431 |  | miss | — | — | — | — |
| SL-0432 |  | miss | — | — | — | — |
| SL-0433 |  | miss | — | — | — | — |
| SL-0434 |  | miss | — | — | — | — |
| SL-0435 |  | miss | — | — | — | — |
| SL-0436 |  | miss | — | — | — | — |
| SL-0437 |  | miss | — | — | — | — |
| SL-0438 |  | miss | — | — | — | — |
| SL-0439 |  | miss | — | — | — | — |
| SL-0440 |  | miss | — | — | — | — |
| SL-0441 |  | miss | — | — | — | — |
| SL-0442 |  | miss | — | — | — | — |
| SL-0443 |  | miss | — | — | — | — |
| SL-0444 |  | miss | — | — | — | — |
| SL-0445 |  | miss | — | — | — | — |
| SL-0446 |  | miss | — | — | — | — |
| SL-0447 |  | miss | — | — | — | — |
| SL-0448 |  | miss | — | — | — | — |
| SL-0449 |  | miss | — | — | — | — |
| SL-0450 |  | miss | — | — | — | — |
| SL-0451 |  | miss | — | — | — | — |
| SL-0452 |  | miss | — | — | — | — |
| SL-0453 |  | miss | — | — | — | — |
| SL-0454 |  | miss | — | — | — | — |
| SL-0455 |  | miss | — | — | — | — |
| SL-0456 |  | miss | — | — | — | — |
| SL-0457 |  | miss | — | — | — | — |
| SL-0458 |  | miss | — | — | — | — |
| SL-0459 |  | miss | — | — | — | — |
| SL-0460 |  | miss | — | — | — | — |
| SL-0461 |  | miss | — | — | — | — |
| SL-0462 |  | miss | — | — | — | — |
| SL-0463 |  | miss | — | — | — | — |
| SL-0464 |  | miss | — | — | — | — |
| SL-0465 |  | miss | — | — | — | — |
| SL-0466 |  | miss | — | — | — | — |
| SL-0467 |  | miss | — | — | — | — |
| SL-0468 |  | miss | — | — | — | — |
| SL-0469 |  | miss | — | — | — | — |
| SL-0470 |  | miss | — | — | — | — |
| SL-0471 |  | miss | — | — | — | — |
| SL-0472 |  | miss | — | — | — | — |
| SL-0473 |  | miss | — | — | — | — |
| SL-0474 |  | miss | — | — | — | — |
| SL-0475 |  | miss | — | — | — | — |
| SL-0476 |  | miss | — | — | — | — |
| SL-0477 |  | miss | — | — | — | — |
| SL-0478 | yes | ok | — | — | — | — |
| SL-0479 | yes | ok | — | — | — | — |
| SL-0480 | yes | ok | — | — | — | — |
| SL-0481 | yes | ok | — | — | — | — |
| SL-0482 | yes | ok | — | — | — | — |
| SL-0483 | yes | ok | — | — | — | — |
| SL-0484 | yes | ok | — | — | — | — |
| SL-0485 | yes | ok | — | — | — | — |
| SL-0486 | yes | ok | — | — | — | — |
| SL-0487 | yes | ok | — | — | — | — |
| SL-0488 | yes | ok | — | — | — | — |
| SL-0489 | yes | ok | — | — | — | — |
| SL-0490 | yes | ok | — | — | — | — |
| SL-0491 | yes | ok | — | — | — | — |
| SL-0492 | yes | ok | — | — | — | — |
| SL-0493 | yes | ok | — | — | — | — |
| SL-0494 | yes | ok | — | — | — | — |
| SL-0495 | yes | ok | — | — | — | — |
| SL-0496 | yes | ok | — | — | — | — |
| SL-0497 | yes | ok | — | — | — | — |
| SL-0498 | yes | ok | — | — | — | — |
| SL-0499 | yes | ok | — | — | — | — |
| SL-0500 | yes | ok | — | — | — | — |
| SL-0501 | yes | ok | — | — | — | — |
| SL-0502 | yes | ok | — | — | — | — |
| SL-0503 | yes | ok | — | — | — | — |
| SL-0504 | yes | ok | — | — | — | — |
| SL-0505 | yes | ok | — | — | — | — |
| SL-0506 | yes | ok | — | — | — | — |
| SL-0507 |  | hit | DH | — | yes | — |
| SL-0508 |  | hit | DH | — | yes | — |
| SL-0509 |  | hit | DH | — | yes | — |
| SL-0510 |  | hit | DH | — | yes | — |
| SL-0511 |  | hit | DH | — | yes | — |
| SL-0512 |  | hit | DH | — | yes | — |
| SL-0513 |  | hit | DH | — | yes | — |
| SL-0514 |  | hit | DH | — | yes | — |
| SL-0515 |  | hit | DH | — | yes | — |
| SL-0516 |  | hit | RSA | — | no | no |
| SL-0517 |  | hit | RSA | — | no | no |
| SL-0518 |  | parent_only | EC | — | — | — |
| SL-0519 |  | miss | — | — | — | — |
| SL-0520 |  | parent_only | EC | — | — | — |
| SL-0521 |  | parent_only | EC | — | — | — |
| SL-0522 |  | parent_only | EC | — | — | — |
| SL-0523 |  | miss | — | — | — | — |
| SL-0524 |  | miss | — | — | — | — |
| SL-0525 |  | miss | — | — | — | — |
| SL-0526 |  | hit | ML-KEM | — | yes | — |
| SL-0527 |  | hit | ML-KEM | — | yes | — |
| SL-0528 |  | hit | ML-KEM | — | yes | — |
| SL-0529 | yes | ok | — | — | — | — |
| SL-0530 | yes | false_alarm | DH | — | — | — |
| SL-0531 | yes | false_alarm | EC | — | — | — |
| SL-0532 |  | hit | DSA | — | yes | — |
| SL-0533 |  | hit | RSA | — | no | — |
| SL-0534 |  | hit | RSA | — | no | — |
| SL-0535 |  | hit | RSA | — | no | — |
| SL-0536 |  | hit | RSA | — | no | — |
| SL-0537 |  | miss | — | — | — | — |
| SL-0538 |  | hit | RSA | — | no | — |
| SL-0539 |  | miss | — | — | — | — |
| SL-0540 |  | parent_only | EC | — | — | — |
| SL-0541 |  | parent_only | EC | — | — | — |
| SL-0542 |  | parent_only | EC | — | — | — |
| SL-0543 |  | hit | DSA | — | yes | — |
| SL-0544 |  | hit | RSA | — | no | — |
| SL-0545 |  | hit | RSA | — | no | no |
| SL-0546 |  | parent_only | EC | — | — | — |
| SL-0547 |  | parent_only | EC | — | — | — |
| SL-0548 |  | parent_only | EC | — | — | — |
| SL-0549 |  | parent_only | EC | — | — | — |
| SL-0550 |  | miss | — | — | — | — |
| SL-0551 |  | hit | ML-DSA | — | yes | — |
| SL-0552 |  | hit | ML-DSA | — | yes | — |
| SL-0553 |  | hit | ML-DSA | — | yes | — |
| SL-0554 |  | hit | EC, ML-DSA | — | yes | — |
| SL-0555 |  | hit | ML-DSA | — | yes | — |
| SL-0556 | yes | false_alarm | DSA | — | — | — |
| SL-0557 | yes | ok | — | — | — | — |
| SL-0558 | yes | false_alarm | EC | — | — | — |
| SL-0559 |  | miss | — | — | — | — |
| SL-0560 |  | miss | — | — | — | — |
| SL-0561 |  | miss | — | — | — | — |
| SL-0562 |  | miss | — | — | — | — |
| SL-0563 |  | miss | — | — | — | — |
| SL-0564 |  | miss | — | — | — | — |
| SL-0565 |  | miss | — | — | — | — |
| SL-0566 |  | miss | — | — | — | — |
| SL-0567 |  | miss | — | — | — | — |
| SL-0568 |  | miss | — | — | — | — |
| SL-0569 |  | miss | — | — | — | — |
| SL-0570 |  | miss | — | — | — | — |
| SL-0571 |  | miss | — | — | — | — |
| SL-0572 |  | miss | — | — | — | — |
| SL-0573 |  | miss | — | — | — | — |
| SL-0574 |  | miss | — | — | — | — |
| SL-0575 |  | miss | — | — | — | — |
| SL-0576 |  | miss | — | — | — | — |
| SL-0577 |  | miss | — | — | — | — |
| SL-0578 |  | miss | — | — | — | — |
| SL-0579 |  | parent_only | EC | — | — | — |
| SL-0580 |  | miss | — | — | — | — |
| SL-0581 |  | hit | ML-KEM | — | yes | — |
| SL-0582 |  | hit | ML-KEM | — | yes | — |
| SL-0583 |  | hit | ML-KEM | — | yes | — |
| SL-0584 | yes | ok | — | — | — | — |
| SL-0585 | yes | ok | — | — | — | — |
| SL-0586 | yes | ok | — | — | — | — |
| SL-0587 |  | hit | RSA | — | no | — |
| SL-0588 |  | miss | — | — | — | — |
| SL-0589 |  | parent_only | EC | — | — | — |
| SL-0590 |  | parent_only | EC | — | — | — |
| SL-0591 |  | parent_only | EC | — | — | — |
| SL-0592 | yes | false_alarm | RSA | — | — | — |
| SL-0593 |  | miss | — | — | — | — |
| SL-0594 |  | miss | — | — | — | — |
| SL-0595 |  | miss | — | — | — | — |
| SL-0596 |  | miss | — | — | — | — |
| SL-0597 |  | miss | — | — | — | — |
| SL-0598 |  | miss | — | — | — | — |
| SL-0599 |  | miss | — | — | — | — |
| SL-0600 |  | miss | — | — | — | — |
| SL-0601 |  | miss | — | — | — | — |
| SL-0602 |  | hit | RSA | — | no | — |
| SL-0603 |  | hit | RSA | — | no | — |
| SL-0604 |  | parent_only | EC | — | — | — |
| SL-0605 |  | parent_only | EC | — | — | — |
| SL-0606 |  | parent_only | EC | — | — | — |
| SL-0607 |  | parent_only | EC | — | — | — |
| SL-0608 |  | miss | — | — | — | — |
| SL-0609 |  | miss | — | — | — | — |
| SL-0610 |  | hit | RSA | — | no | — |
| SL-0611 |  | hit | RSA | — | no | — |
| SL-0612 |  | miss | — | — | — | — |
| SL-0613 |  | hit | ML-DSA | — | yes | — |
| SL-0614 |  | hit | ML-DSA | — | yes | — |
| SL-0615 |  | hit | ML-DSA | — | yes | — |
| SL-0616 |  | parent_only | EC | — | — | — |
| SL-0617 |  | miss | — | — | — | — |
| SL-0618 |  | miss | — | — | — | — |
| SL-0619 |  | miss | — | — | — | — |
| SL-0620 |  | miss | — | — | — | — |
| SL-0621 |  | miss | — | — | — | — |
| SL-0622 |  | miss | — | — | — | — |
| SL-0623 |  | miss | — | — | — | — |
| SL-0624 |  | miss | — | — | — | — |
| SL-0625 |  | miss | — | — | — | — |
| SL-0626 |  | miss | — | — | — | — |
| SL-0627 |  | miss | — | — | — | — |
| SL-0628 |  | miss | — | — | — | — |
| SL-0629 |  | miss | — | — | — | — |
| SL-0630 |  | miss | — | — | — | — |
| SL-0631 |  | miss | — | — | — | — |
| SL-0632 | yes | ok | — | — | — | — |
| SL-0633 | yes | ok | — | — | — | — |
| SL-0634 | yes | ok | — | — | — | — |
| SL-0635 | yes | ok | — | — | — | — |
| SL-0636 |  | miss | — | — | — | — |
| SL-0637 |  | hit | RSA | — | — | — |
| SL-0638 | yes | ok | — | — | — | — |
| SL-0639 |  | hit | EC | — | — | no |
| SL-0640 |  | hit | EC | — | — | no |
| SL-0641 |  | hit | EC | — | — | no |
| SL-0642 |  | parent_only | EC | — | — | — |
| SL-0643 |  | miss | — | — | — | — |
| SL-0644 |  | miss | — | — | — | — |
| SL-0645 |  | miss | — | — | — | — |
| SL-0646 |  | miss | — | — | — | — |
| SL-0647 | yes | false_alarm | EC | — | — | — |
| SL-0648 |  | miss | — | — | — | — |
| SL-0649 |  | miss | — | — | — | — |
| SL-0650 |  | miss | — | — | — | — |
| SL-0651 |  | miss | — | — | — | — |
| SL-0652 |  | miss | — | — | — | — |
| SL-0653 |  | miss | — | — | — | — |
| SL-0654 |  | miss | — | — | — | — |
| SL-0655 |  | miss | — | — | — | — |
| SL-0656 |  | miss | — | — | — | — |
| SL-0657 |  | miss | — | — | — | — |
| SL-0658 |  | miss | — | — | — | — |
| SL-0659 |  | hit | ML-DSA | — | yes | — |
| SL-0660 |  | hit | ML-DSA | — | yes | — |
| SL-0661 |  | hit | ML-DSA | — | yes | — |
| SL-0662 |  | miss | — | — | — | — |
| SL-0663 |  | hit | LMS | — | yes | — |
| SL-0664 |  | miss | — | — | — | — |
| SL-0665 |  | miss | — | — | — | — |
| SL-0666 |  | miss | — | — | — | — |
| SL-0667 |  | miss | — | — | — | — |
| SL-0668 |  | miss | — | — | — | — |
| SL-0669 |  | miss | — | — | — | — |
| SL-0670 |  | miss | — | — | — | — |
| SL-0671 |  | miss | — | — | — | — |
| SL-0672 |  | parent_only | EC | — | — | — |
| SL-0673 |  | parent_only | EC | — | — | — |
| SL-0674 |  | parent_only | EC | — | — | — |
| SL-0675 |  | parent_only | EC | — | — | — |
| SL-0676 |  | parent_only | EC | — | — | — |
| SL-0677 |  | parent_only | EC | — | — | — |
| SL-0678 |  | parent_only | EC | — | — | — |
| SL-0679 |  | parent_only | EC | — | — | — |
| SL-0680 |  | parent_only | EC | — | — | — |
| SL-0681 |  | parent_only | EC | — | — | — |
| SL-0682 |  | parent_only | EC | — | — | — |
| SL-0683 |  | miss | — | — | — | — |
| SL-0684 |  | miss | — | — | — | — |
| SL-0685 |  | miss | — | — | — | — |
| SL-0686 | yes | ok | — | — | — | — |
| SL-0687 | yes | ok | — | — | — | — |
| SL-0688 | yes | ok | — | — | — | — |
| SL-0689 | yes | false_alarm | EC | — | — | — |
| SL-0690 |  | hit | EC | — | — | no |
| SL-0691 |  | hit | EC | — | — | no |
| SL-0692 |  | hit | EC | — | — | no |
| SL-0693 |  | miss | — | — | — | — |
| SL-0694 |  | miss | — | — | — | — |
| SL-0695 |  | parent_only | EC | — | — | — |
| SL-0696 |  | miss | — | — | — | — |
| SL-0697 |  | miss | — | — | — | — |
| SL-0698 |  | miss | — | — | — | — |
| SL-0699 |  | miss | — | — | — | — |
| SL-0700 |  | miss | — | — | — | — |
| SL-0701 |  | miss | — | — | — | — |
| SL-0702 | yes | ok | — | — | — | — |
| SL-0703 | yes | ok | — | — | — | — |
| SL-0704 |  | miss | — | — | — | — |
| SL-0705 |  | hit | RSA | — | — | — |
| SL-0706 |  | hit | LMS | — | yes | — |
| SL-0707 | yes | ok | — | — | — | — |
| SL-1000 |  | miss | — | — | — | — |
| SL-1001 |  | miss | — | — | — | — |
| SL-1002 |  | miss | — | — | — | — |
| SL-1003 |  | miss | — | — | — | — |
| SL-1004 |  | miss | — | — | — | — |
| SL-1005 |  | miss | — | — | — | — |
| SL-1006 |  | miss | — | — | — | — |
| SL-1007 |  | miss | — | — | — | — |
| SL-1008 |  | miss | — | — | — | — |
| SL-1009 |  | miss | — | — | — | — |
| SL-1010 |  | miss | — | — | — | — |
| SL-1011 |  | miss | — | — | — | — |
| SL-1012 |  | miss | — | — | — | — |
| SL-1013 |  | miss | — | — | — | — |
| SL-1014 |  | miss | — | — | — | — |
| SL-1015 |  | miss | — | — | — | — |
| SL-1016 |  | miss | — | — | — | — |
| SL-1017 |  | miss | — | — | — | — |
| SL-1018 | yes | ok | — | — | — | — |
| SL-1019 | yes | ok | — | — | — | — |
| SL-1020 | yes | ok | — | — | — | — |
| SL-1021 | yes | ok | — | — | — | — |
| SL-1022 |  | miss | — | — | — | — |
| SL-1023 |  | miss | — | — | — | — |
| SL-1024 |  | miss | — | — | — | — |
| SL-1025 |  | miss | — | — | — | — |
| SL-1026 |  | miss | — | — | — | — |
| SL-1027 |  | miss | — | — | — | — |
| SL-1028 |  | miss | — | — | — | — |
| SL-1029 |  | miss | — | — | — | — |
| SL-1030 |  | miss | — | — | — | — |
| SL-1031 |  | miss | — | — | — | — |
| SL-1032 |  | miss | — | — | — | — |
| SL-1033 |  | miss | — | — | — | — |
| SL-1034 |  | miss | — | — | — | — |
| SL-1035 |  | miss | — | — | — | — |
| SL-1036 |  | miss | — | — | — | — |
| SL-1037 |  | miss | — | — | — | — |
| SL-1038 |  | miss | — | — | — | — |
| SL-1039 |  | miss | — | — | — | — |
| SL-1040 |  | miss | — | — | — | — |
| SL-1041 |  | miss | — | — | — | — |
| SL-1042 |  | miss | — | — | — | — |
| SL-1043 |  | miss | — | — | — | — |
| SL-1044 |  | miss | — | — | — | — |
| SL-1045 |  | miss | — | — | — | — |
| SL-1046 |  | miss | — | — | — | — |
| SL-1047 |  | miss | — | — | — | — |
| SL-1048 |  | miss | — | — | — | — |
| SL-1049 |  | miss | — | — | — | — |
| SL-1050 |  | miss | — | — | — | — |
| SL-1051 |  | miss | — | — | — | — |
| SL-1052 |  | miss | — | — | — | — |
| SL-1053 |  | miss | — | — | — | — |
| SL-1054 |  | miss | — | — | — | — |
| SL-1055 |  | miss | — | — | — | — |
| SL-1056 |  | miss | — | — | — | — |
| SL-1057 |  | miss | — | — | — | — |
| SL-1058 |  | miss | — | — | — | — |
| SL-1059 |  | miss | — | — | — | — |
| SL-1060 |  | miss | — | — | — | — |
| SL-1061 |  | miss | — | — | — | — |
| SL-1062 |  | miss | — | — | — | — |
| SL-1063 |  | miss | — | — | — | — |
| SL-1064 |  | miss | — | — | — | — |
| SL-1065 |  | miss | — | — | — | — |
| SL-1066 |  | miss | — | — | — | — |
| SL-1067 |  | hit | EC | — | — | no |
| SL-1068 |  | hit | EC | — | — | no |
| SL-1069 |  | hit | EC | — | — | no |
| SL-1070 |  | miss | — | — | — | — |
| SL-1071 |  | miss | — | — | — | — |
| SL-1072 |  | miss | — | — | — | — |
| SL-1073 |  | miss | — | — | — | — |
| SL-1074 |  | miss | — | — | — | — |
| SL-1075 |  | miss | — | — | — | — |
| SL-1076 |  | miss | — | — | — | — |
| SL-1077 |  | miss | — | — | — | — |
| SL-1078 |  | miss | — | — | — | — |
| SL-1079 |  | miss | — | — | — | — |
| SL-1080 |  | miss | — | — | — | — |
| SL-1081 |  | parent_only | EC | — | — | — |
| SL-1082 |  | miss | — | — | — | — |
| SL-1083 |  | miss | — | — | — | — |
| SL-1084 |  | miss | — | — | — | — |
| SL-1085 |  | miss | — | — | — | — |
| SL-1086 |  | miss | — | — | — | — |
| SL-1087 |  | miss | — | — | — | — |
| SL-1088 |  | miss | — | — | — | — |
| SL-1089 | yes | ok | — | — | — | — |
| SL-1090 | yes | ok | — | — | — | — |
| SL-1091 | yes | ok | — | — | — | — |
| SL-1092 | yes | ok | — | — | — | — |
| SL-1093 |  | miss | — | — | — | — |
| SL-1094 |  | miss | — | — | — | — |
| SL-1095 |  | miss | — | — | — | — |
| SL-1096 |  | miss | — | — | — | — |
| SL-1097 |  | miss | — | — | — | — |
| SL-1098 |  | miss | — | — | — | — |
| SL-1099 |  | miss | — | — | — | — |
| SL-1100 |  | miss | — | — | — | — |
| SL-1101 |  | miss | — | — | — | — |
| SL-1102 |  | miss | — | — | — | — |
| SL-1103 |  | miss | — | — | — | — |
| SL-1104 |  | miss | — | — | — | — |
| SL-1105 |  | miss | — | — | — | — |
| SL-1106 |  | miss | — | — | — | — |
| SL-1107 |  | miss | — | — | — | — |
| SL-1108 |  | miss | — | — | — | — |
| SL-1109 |  | miss | — | — | — | — |
| SL-1110 |  | miss | — | — | — | — |
| SL-1111 |  | miss | — | — | — | — |
| SL-1112 |  | miss | — | — | — | — |
| SL-1113 | yes | ok | — | — | — | — |
| SL-1114 |  | hit | RSA | — | — | no |
| SL-1115 |  | miss | — | — | — | — |
| SL-1116 |  | parent_only | EC | — | — | — |
| SL-1117 |  | parent_only | EC | — | — | — |
| SL-1118 |  | hit | ML-KEM | — | yes | — |
| SL-1119 |  | hit | ML-DSA | — | yes | — |
| SL-1120 |  | hit | SLH-DSA | — | yes | — |
| SL-1121 |  | hit | RSA | — | — | no |
| SL-1122 |  | miss | — | — | — | — |
| SL-1123 |  | hit | EC | — | — | no |
| SL-1124 |  | parent_only | EC | — | — | — |
| SL-1125 |  | miss | — | — | — | — |
| SL-1126 |  | miss | — | — | — | — |
| SL-1127 |  | miss | — | — | — | — |
| SL-1128 |  | hit | EC | — | — | no |
| SL-1129 |  | miss | — | — | — | — |
| SL-1130 |  | miss | — | — | — | — |
| SL-1131 |  | hit | ML-DSA | — | yes | — |
| SL-1132 |  | hit | ML-KEM | — | yes | — |
| SL-1133 |  | miss | — | — | — | — |
| SL-1134 |  | miss | — | — | — | — |
| SL-1135 |  | hit | RSA | — | — | no |
| SL-1136 |  | hit | EC | — | — | no |
| SL-1137 |  | parent_only | EC | — | — | — |
| SL-1138 |  | miss | — | — | — | — |
| SL-1139 |  | miss | — | — | — | — |
| SL-1140 |  | hit | ML-KEM | — | yes | — |
| SL-1141 |  | hit | ML-DSA | — | yes | — |
| SL-1142 |  | hit | SLH-DSA | — | yes | — |
| SL-1143 |  | hit | LMS | — | yes | — |
| SL-1144 |  | hit | XMSS | — | yes | — |
| SL-1145 |  | hit | RSA | — | — | no |
| SL-1146 |  | hit | EC | — | — | no |
| SL-1147 |  | parent_only | EC | — | — | — |
| SL-1148 |  | miss | — | — | — | — |
| SL-1149 |  | wrong_family | RSA | — | — | — |
| SL-1150 |  | miss | — | — | — | — |
| SL-1151 |  | hit | ML-KEM | — | yes | — |
| SL-1152 |  | hit | ML-DSA | — | yes | — |
| SL-1153 |  | hit | SLH-DSA | — | yes | — |
| SL-1154 |  | parent_only | EC | — | — | — |
| SL-1155 |  | hit | ML-KEM | — | yes | — |
| SL-1156 |  | parent_only | EC | — | — | — |
| SL-1157 |  | parent_only | EC | — | — | — |
| SL-1158 |  | miss | — | — | — | — |
| SL-1159 | yes | ok | — | — | — | — |
| SL-1160 | yes | false_alarm | EC | — | — | — |
| SL-1161 | yes | ok | — | — | — | — |
| SL-1162 | yes | false_alarm | ML-KEM | — | — | — |
| SL-1163 | yes | ok | — | — | — | — |
| SL-1164 |  | miss | — | — | — | — |
| SL-1165 |  | miss | — | — | — | — |
| SL-1166 |  | miss | — | — | — | — |
| SL-1167 |  | miss | — | — | — | — |
| SL-1168 |  | hit | ML-KEM | — | yes | — |
| SL-1169 |  | miss | — | — | — | — |
| SL-1170 |  | parent_only | EC | — | — | — |
| SL-1171 |  | miss | — | — | — | — |
| SL-1172 |  | parent_only | EC | — | — | — |
| SL-1173 |  | hit | EC, ML-DSA | — | yes | — |
| SL-1174 |  | parent_only | EC | — | — | — |
| SL-1175 |  | hit | DH | — | yes | — |
| SL-1176 |  | parent_only | EC | — | — | — |
| SL-1177 |  | miss | — | — | — | — |
| SL-1178 |  | parent_only | EC | — | — | — |
| SL-1183 |  | miss | — | — | — | — |
| SL-1184 |  | hit | RSA | — | no | — |
| SL-1185 |  | parent_only | EC | — | — | — |
| SL-1186 |  | miss | — | — | — | — |
| SL-1187 |  | miss | — | — | — | — |
| SL-1188 |  | hit | RSA | — | no | — |
| SL-1189 | yes | false_alarm | DH | — | — | — |
| SL-1190 | yes | false_alarm | EC | — | — | — |
| SL-1191 | yes | ok | — | — | — | — |
| SL-1192 | yes | false_alarm | EC | — | — | — |
| SL-1194 |  | miss | — | — | — | — |
| SL-2000 |  | miss | — | — | — | — |
| SL-2001 |  | miss | — | — | — | — |
| SL-2002 |  | miss | — | — | — | — |
| SL-2003 |  | parent_only | EC | — | — | — |
| SL-2004 |  | miss | — | — | — | — |
| SL-2005 |  | miss | — | — | — | — |
| SL-2006 |  | hit | RSA | — | — | — |
| SL-2007 |  | miss | — | — | — | — |
| SL-2008 |  | miss | — | — | — | — |
| SL-2009 |  | miss | — | — | — | — |
| SL-2010 |  | hit | ML-KEM | — | yes | — |
| SL-2011 |  | miss | — | — | — | — |
| SL-2012 |  | hit | ML-KEM | — | yes | — |
| SL-2013 |  | miss | — | — | — | — |
| SL-2014 |  | parent_only | EC | — | — | — |
| SL-2015 |  | miss | — | — | — | — |
| SL-2016 |  | miss | — | — | — | — |
| SL-2017 |  | parent_only | EC | — | — | — |
| SL-2018 |  | hit | ML-DSA | — | yes | — |
| SL-2019 |  | miss | — | — | — | — |
| SL-2020 |  | miss | — | — | — | — |
| SL-2021 |  | hit | ML-KEM | — | yes | — |
| SL-2022 |  | hit | ML-KEM | — | yes | — |
| SL-2023 |  | miss | — | — | — | — |
| SL-2024 |  | miss | — | — | — | — |
| SL-2025 |  | miss | — | — | — | — |
| SL-2026 |  | miss | — | — | — | — |
| SL-2027 |  | parent_only | EC | — | — | — |
| SL-2028 |  | miss | — | — | — | — |
| SL-2029 |  | miss | — | — | — | — |
| SL-2030 |  | hit | RSA | — | no | no |
| SL-2031 |  | hit | RSA | — | no | — |
| SL-2032 |  | hit | RSA | — | — | no |
| SL-2033 |  | hit | RSA | — | no | — |
| SL-2034 |  | hit | RSA | — | no | — |
| SL-2035 |  | hit | RSA | — | no | — |
| SL-2036 |  | hit | RSA | — | no | — |
| SL-2037 |  | parent_only | EC | — | — | — |
| SL-2038 |  | parent_only | EC | — | — | — |
| SL-2039 |  | parent_only | EC | — | — | — |
| SL-2040 |  | parent_only | EC | — | — | — |
| SL-2041 |  | miss | — | — | — | — |
| SL-2042 |  | miss | — | — | — | — |
| SL-2043 |  | miss | — | — | — | — |
| SL-2044 |  | miss | — | — | — | — |
| SL-2045 |  | hit | ML-KEM | — | yes | — |
| SL-2046 |  | hit | ML-DSA | — | yes | — |
| SL-2047 |  | hit | SLH-DSA | — | yes | — |
| SL-2048 |  | miss | — | — | — | — |
| SL-2049 | yes | ok | — | — | — | — |
| SL-2050 | yes | false_alarm | ML-KEM | — | — | — |
| SL-2051 | yes | ok | — | — | — | — |
| SL-2052 | yes | ok | — | — | — | — |
| SL-2053 |  | hit | RSA | — | — | no |
| SL-2054 |  | miss | — | — | — | — |
| SL-2055 |  | miss | — | — | — | — |
| SL-2056 |  | miss | — | — | — | — |
| SL-2057 |  | miss | — | — | — | — |
| SL-2058 |  | miss | — | — | — | — |
| SL-2059 |  | miss | — | — | — | — |
| SL-2060 |  | hit | ML-KEM | — | yes | — |
| SL-2061 |  | miss | — | — | — | — |
| SL-2062 |  | miss | — | — | — | — |
| SL-2063 |  | miss | — | — | — | — |
| SL-2064 |  | hit | RSA | — | no | — |
| SL-2065 |  | miss | — | — | — | — |
| SL-2066 |  | miss | — | — | — | — |
| SL-2067 |  | miss | — | — | — | — |
| SL-2068 |  | miss | — | — | — | — |
| SL-2069 |  | miss | — | — | — | — |
| SL-2070 |  | miss | — | — | — | — |
| SL-2071 |  | hit | EC | — | — | no |
| SL-2072 |  | hit | RSA | — | — | — |
| SL-2073 |  | miss | — | — | — | — |
| SL-2074 |  | miss | — | — | — | — |
| SL-2075 |  | miss | — | — | — | — |
| SL-2076 |  | miss | — | — | — | — |
| SL-2077 |  | miss | — | — | — | — |
| SL-2078 |  | miss | — | — | — | — |
| SL-2079 |  | miss | — | — | — | — |
| SL-2080 | yes | false_alarm | ML-KEM | — | — | — |
| SL-2081 | yes | ok | — | — | — | — |
| SL-2082 |  | miss | — | — | — | — |
| SL-2083 |  | miss | — | — | — | — |
| SL-2084 |  | miss | — | — | — | — |
| SL-2085 |  | miss | — | — | — | — |
| SL-2086 |  | miss | — | — | — | — |
| SL-2087 |  | miss | — | — | — | — |
| SL-2088 |  | miss | — | — | — | — |
| SL-2089 |  | miss | — | — | — | — |
| SL-2090 |  | miss | — | — | — | — |
| SL-2091 | yes | ok | — | — | — | — |
| SL-2092 |  | miss | — | — | — | — |
| SL-2093 |  | miss | — | — | — | — |
| SL-2094 |  | miss | — | — | — | — |
| SL-2095 |  | hit | RSA | — | — | no |
| SL-2096 |  | miss | — | — | — | — |
| SL-2097 |  | miss | — | — | — | — |
| SL-2098 |  | miss | — | — | — | — |
| SL-2099 |  | miss | — | — | — | — |
| SL-2100 |  | miss | — | — | — | — |
| SL-2101 |  | miss | — | — | — | — |
| SL-2102 |  | miss | — | — | — | — |
| SL-2103 |  | miss | — | — | — | — |
| SL-2104 |  | miss | — | — | — | — |
| SL-2105 |  | miss | — | — | — | — |
| SL-2106 |  | miss | — | — | — | — |
| SL-2107 |  | miss | — | — | — | — |
| SL-2108 |  | miss | — | — | — | — |
| SL-2109 |  | miss | — | — | — | — |
| SL-2110 |  | miss | — | — | — | — |
| SL-2111 |  | miss | — | — | — | — |
| SL-2112 |  | miss | — | — | — | — |
| SL-2113 |  | miss | — | — | — | — |
| SL-2114 | yes | ok | — | — | — | — |
| SL-2115 | yes | ok | — | — | — | — |
| SL-2116 | yes | ok | — | — | — | — |
| SL-2117 |  | miss | — | — | — | — |
| SL-2118 |  | miss | — | — | — | — |
| SL-2119 |  | miss | — | — | — | — |
| SL-2120 |  | miss | — | — | — | — |
| SL-2121 |  | miss | — | — | — | — |
| SL-2122 |  | miss | — | — | — | — |
| SL-2123 |  | miss | — | — | — | — |
| SL-2124 |  | miss | — | — | — | — |
| SL-2125 |  | miss | — | — | — | — |
| SL-2126 |  | miss | — | — | — | — |
| SL-2127 |  | hit | XMSS | — | yes | — |
| SL-2128 |  | miss | — | — | — | — |
| SL-2129 |  | miss | — | — | — | — |
| SL-2130 |  | miss | — | — | — | — |
| SL-2131 |  | miss | — | — | — | — |
| SL-2132 |  | miss | — | — | — | — |
| SL-2133 | yes | ok | — | — | — | — |
| SL-2134 | yes | ok | — | — | — | — |
| SL-2135 |  | miss | — | — | — | — |
| SL-2136 |  | miss | — | — | — | — |
| SL-2137 |  | miss | — | — | — | — |
| SL-2138 |  | miss | — | — | — | — |
| SL-2139 |  | miss | — | — | — | — |
| SL-2140 |  | miss | — | — | — | — |
| SL-2141 |  | miss | — | — | — | — |
| SL-2142 |  | miss | — | — | — | — |
| SL-2143 |  | miss | — | — | — | — |
| SL-2144 |  | miss | — | — | — | — |
| SL-2145 | yes | ok | — | — | — | — |
| SL-2146 |  | miss | — | — | — | — |
| SL-2147 |  | miss | — | — | — | — |
| SL-2148 |  | hit | ML-KEM | — | yes | — |
| SL-2149 |  | miss | — | — | — | — |
| SL-2150 |  | miss | — | — | — | — |
| SL-2151 |  | miss | — | — | — | — |
| SL-2152 |  | miss | — | — | — | — |
| SL-2153 | yes | ok | — | — | — | — |
| SL-2154 |  | miss | — | — | — | — |
| SL-2155 |  | miss | — | — | — | — |
| SL-2156 |  | miss | — | — | — | — |
| SL-2157 |  | miss | — | — | — | — |
| SL-2158 |  | hit | ML-KEM | — | yes | — |
| SL-2159 |  | miss | — | — | — | — |
| SL-2160 |  | hit | LMS | — | yes | — |
| SL-2161 |  | hit | EC | — | — | no |
| SL-2162 |  | miss | — | — | — | — |
| SL-2163 |  | miss | — | — | — | — |
| SL-2164 |  | parent_only | EC | — | — | — |
| SL-2165 |  | hit | ML-KEM | — | yes | — |
| SL-2166 |  | miss | — | — | — | — |
| SL-2167 |  | hit | RSA | — | — | no |
| SL-2168 | yes | ok | — | — | — | — |
| SL-2169 |  | hit | RSA | — | — | — |
| SL-2170 |  | miss | — | — | — | — |
| SL-2171 |  | miss | — | — | — | — |
| SL-2172 |  | miss | — | — | — | — |
| SL-2173 |  | parent_only | EC | — | — | — |
| SL-2174 |  | parent_only | EC | — | — | — |
| SL-2175 |  | parent_only | EC | — | — | — |
| SL-2176 |  | parent_only | EC | — | — | — |
| SL-2177 |  | miss | — | — | — | — |
| SL-2178 |  | miss | — | — | — | — |
| SL-2179 |  | hit | EC | — | — | no |
| SL-2180 | yes | ok | — | — | — | — |
| SL-2181 | yes | ok | — | — | — | — |
| SL-2500 |  | miss | — | — | — | — |
| SL-2501 |  | miss | — | — | — | — |
| SL-2502 |  | miss | — | — | — | — |
| SL-2503 |  | hit | EC | — | — | no |
| SL-2504 |  | miss | — | — | — | — |
| SL-2505 |  | miss | — | — | — | — |
| SL-2506 |  | miss | — | — | — | — |
| SL-2507 |  | miss | — | — | — | — |
| SL-2508 |  | hit | EC | — | — | no |
| SL-2509 |  | miss | — | — | — | — |
| SL-2510 |  | miss | — | — | — | — |
| SL-2511 |  | miss | — | — | — | — |
| SL-2512 |  | miss | — | — | — | — |
| SL-2513 |  | miss | — | — | — | — |
| SL-2514 |  | miss | — | — | — | — |
| SL-2515 |  | hit | RSA | — | — | no |
| SL-2516 |  | parent_only | EC | — | — | — |
| SL-2517 |  | hit | EC | — | — | no |
| SL-2518 |  | hit | EC | — | — | no |
| SL-2519 |  | parent_only | EC | — | — | — |
| SL-2520 |  | miss | — | — | — | — |
| SL-2521 |  | hit | DH | — | yes | no |
| SL-2522 | yes | ok | — | — | — | — |
| SL-2523 | yes | ok | — | — | — | — |
| SL-2524 | yes | ok | — | — | — | — |
| SL-2525 |  | hit | RSA | — | — | no |
| SL-2526 |  | hit | RSA | — | — | no |
| SL-2527 |  | hit | EC | — | — | no |
| SL-2528 |  | hit | EC | — | — | no |
| SL-2529 |  | parent_only | EC | — | — | — |
| SL-2530 |  | miss | — | — | — | — |
| SL-2531 |  | miss | — | — | — | — |
| SL-2532 |  | miss | — | — | — | — |
| SL-2533 |  | hit | ML-DSA | — | yes | — |
| SL-2534 |  | miss | — | — | — | — |
| SL-2535 |  | miss | — | — | — | — |
| SL-2536 |  | miss | — | — | — | — |
| SL-2537 |  | parent_only | EC | — | — | — |
| SL-2538 |  | miss | — | — | — | — |
| SL-2539 |  | parent_only | EC | — | — | — |
| SL-2540 |  | miss | — | — | — | — |
| SL-2541 |  | miss | — | — | — | — |
| SL-2542 | yes | ok | — | — | — | — |
| SL-2543 | yes | ok | — | — | — | — |
| SL-2544 | yes | ok | — | — | — | — |
| SL-2545 |  | miss | — | — | — | — |
| SL-2546 |  | miss | — | — | — | — |
| SL-2547 |  | miss | — | — | — | — |
| SL-2548 |  | miss | — | — | — | — |
| SL-2549 |  | miss | — | — | — | — |
| SL-2550 |  | parent_only | EC | — | — | — |
| SL-2551 |  | parent_only | EC | — | — | — |
| SL-2552 |  | miss | — | — | — | — |
| SL-2553 |  | miss | — | — | — | — |
| SL-2554 |  | parent_only | EC | — | — | — |
| SL-2555 |  | miss | — | — | — | — |
| SL-2556 |  | hit | RSA | — | no | — |
| SL-2557 |  | hit | ML-DSA | — | yes | — |
| SL-2558 | yes | ok | — | — | — | — |
| SL-2559 | yes | ok | — | — | — | — |
| SL-2560 |  | miss | — | — | — | — |
| SL-2561 |  | miss | — | — | — | — |
| SL-2562 |  | miss | — | — | — | — |
| SL-2563 |  | miss | — | — | — | — |
| SL-2564 |  | miss | — | — | — | — |
| SL-2565 |  | parent_only | EC | — | — | — |
| SL-2566 |  | parent_only | EC | — | — | — |
| SL-2567 |  | miss | — | — | — | — |
| SL-2568 |  | hit | ML-KEM | — | yes | — |
| SL-2569 |  | hit | ML-KEM | — | yes | — |
| SL-2570 |  | hit | ML-DSA | — | yes | — |
| SL-2571 |  | hit | ML-DSA | — | yes | — |
| SL-2572 |  | miss | — | — | — | — |
| SL-2573 |  | miss | — | — | — | — |
| SL-2574 |  | miss | — | — | — | — |
| SL-2575 |  | miss | — | — | — | — |
| SL-2576 |  | miss | — | — | — | — |
| SL-2577 |  | miss | — | — | — | — |
| SL-2578 |  | miss | — | — | — | — |
| SL-2579 |  | miss | — | — | — | — |
| SL-2580 |  | miss | — | — | — | — |
| SL-2581 | yes | ok | — | — | — | — |
| SL-2582 | yes | false_alarm | EC | — | — | — |
| SL-2583 |  | hit | RSA | — | no | no |
| SL-2584 |  | hit | RSA | — | no | no |
| SL-2585 |  | hit | RSA | — | no | no |
| SL-2586 |  | parent_only | EC | — | — | — |
| SL-2587 |  | parent_only | EC | — | — | — |
| SL-2588 |  | parent_only | EC | — | — | — |
| SL-2589 |  | parent_only | EC | — | — | — |
| SL-2590 |  | miss | — | — | — | — |
| SL-2591 |  | miss | — | — | — | — |
| SL-2592 |  | miss | — | — | — | — |
| SL-2593 |  | hit | ML-KEM | — | yes | — |
| SL-2594 |  | hit | ML-DSA | — | yes | — |
| SL-2595 |  | hit | SLH-DSA | — | yes | — |
| SL-2596 |  | parent_only | EC | — | — | — |
| SL-2597 |  | miss | — | — | — | — |
| SL-2598 | yes | ok | — | — | — | — |
| SL-2599 | yes | ok | — | — | — | — |
| SL-2600 | yes | false_alarm | RSA | — | — | — |
| SL-2601 |  | parent_only | EC | — | — | — |
| SL-2602 |  | parent_only | EC | — | — | — |
| SL-2603 |  | miss | — | — | — | — |
| SL-2604 |  | wrong_family | DH, RSA | — | — | — |
| SL-2605 |  | parent_only | DH, EC | — | — | — |
| SL-2606 |  | hit | DH, RSA | — | yes | — |
| SL-2607 |  | parent_only | DH, EC | — | — | — |
| SL-2608 | yes | ok | — | — | — | — |
| SL-2609 | yes | false_alarm | DH, RSA | — | — | — |
| SL-3000 |  | hit | RSA | — | — | no |
| SL-3001 |  | hit | RSA | — | — | no |
| SL-3002 |  | hit | RSA | — | — | no |
| SL-3003 |  | miss | — | — | — | — |
| SL-3004 |  | miss | — | — | — | — |
| SL-3005 |  | miss | — | — | — | — |
| SL-3006 |  | miss | — | — | — | — |
| SL-3007 |  | miss | — | — | — | — |
| SL-3008 |  | hit | ML-DSA | — | yes | — |
| SL-3009 |  | hit | ML-DSA | — | yes | — |
| SL-3010 |  | hit | ML-DSA | — | yes | — |
| SL-3011 |  | hit | ML-KEM | — | yes | — |
| SL-3012 |  | hit | ML-KEM | — | yes | — |
| SL-3013 |  | hit | ML-KEM | — | yes | — |
| SL-3014 |  | miss | — | — | — | — |
| SL-3015 | yes | false_alarm | RSA | — | — | — |
| SL-3016 | yes | ok | — | — | — | — |
| SL-3017 |  | hit | RSA | — | no | no |
| SL-3018 |  | miss | — | — | — | — |
| SL-3019 |  | miss | — | — | — | — |
| SL-3020 |  | miss | — | — | — | — |
| SL-3021 |  | miss | — | — | — | — |
| SL-3022 |  | hit | ML-DSA | — | yes | — |
| SL-3023 |  | hit | ML-KEM | — | yes | — |
| SL-3024 | yes | false_alarm | ML-DSA, RSA | — | — | — |
| SL-3025 |  | hit | RSA | — | no | no |
| SL-3026 |  | miss | — | — | — | — |
| SL-3027 |  | miss | — | — | — | — |
| SL-3028 |  | miss | — | — | — | — |
| SL-3029 |  | hit | ML-DSA | — | yes | — |
| SL-3030 |  | hit | ML-KEM | — | yes | — |
| SL-3031 |  | miss | — | — | — | — |
| SL-3032 |  | miss | — | — | — | — |
| SL-3033 |  | miss | — | — | — | — |
| SL-3034 |  | miss | — | — | — | — |
| SL-3035 |  | miss | — | — | — | — |
| SL-3036 |  | miss | — | — | — | — |
| SL-3037 |  | miss | — | — | — | — |
| SL-3038 |  | miss | — | — | — | — |
| SL-3039 |  | miss | — | — | — | — |
| SL-3040 |  | miss | — | — | — | — |
| SL-3041 |  | miss | — | — | — | — |
| SL-3042 |  | miss | — | — | — | — |
| SL-3043 |  | parent_only | EC | — | — | — |
| SL-3044 | yes | ok | — | — | — | — |
| SL-3045 | yes | false_alarm | RSA | — | — | — |
| SL-3046 | yes | ok | — | — | — | — |
| SL-3047 | yes | ok | — | — | — | — |
| SL-3048 |  | hit | RSA | — | — | no |
| SL-3049 |  | hit | RSA | — | — | no |
| SL-3050 |  | hit | RSA | — | — | no |
| SL-3051 |  | miss | — | — | — | — |
| SL-3052 |  | miss | — | — | — | — |
| SL-3053 |  | miss | — | — | — | — |
| SL-3054 |  | miss | — | — | — | — |
| SL-3055 |  | hit | ML-DSA | — | yes | — |
| SL-3056 |  | hit | ML-DSA | — | yes | — |
| SL-3057 |  | hit | ML-DSA | — | yes | — |
| SL-3058 |  | miss | — | — | — | — |
| SL-3059 | yes | false_alarm | RSA | — | — | — |
| SL-3060 | yes | false_alarm | RSA | — | — | — |
| SL-3061 |  | hit | RSA | — | — | no |
| SL-3062 |  | miss | — | — | — | — |
| SL-3063 |  | miss | — | — | — | — |
| SL-3064 |  | hit | RSA | — | — | no |
| SL-3065 |  | miss | — | — | — | — |
| SL-3066 |  | miss | — | — | — | — |
| SL-3067 |  | miss | — | — | — | — |
| SL-3068 |  | hit | RSA | — | — | no |
| SL-3069 |  | miss | — | — | — | — |
| SL-3070 |  | miss | — | — | — | — |
| SL-3071 |  | miss | — | — | — | — |
| SL-3072 |  | miss | — | — | — | — |
| SL-3073 |  | miss | — | — | — | — |
| SL-3074 |  | miss | — | — | — | — |
| SL-3075 |  | miss | — | — | — | — |
| SL-3076 |  | miss | — | — | — | — |
| SL-3077 |  | miss | — | — | — | — |
| SL-3078 |  | miss | — | — | — | — |
| SL-3079 |  | miss | — | — | — | — |
| SL-3080 |  | miss | — | — | — | — |
| SL-3081 |  | miss | — | — | — | — |
| SL-3082 |  | miss | — | — | — | — |
| SL-3083 |  | miss | — | — | — | — |
| SL-3084 |  | miss | — | — | — | — |
| SL-3085 |  | miss | — | — | — | — |
| SL-3086 |  | miss | — | — | — | — |
| SL-3087 |  | miss | — | — | — | — |
| SL-3088 |  | miss | — | — | — | — |
| SL-3089 |  | miss | — | — | — | — |
| SL-3090 |  | miss | — | — | — | — |
| SL-3091 |  | miss | — | — | — | — |
| SL-3092 |  | miss | — | — | — | — |
| SL-3093 |  | miss | — | — | — | — |
| SL-3094 |  | miss | — | — | — | — |
| SL-3095 |  | miss | — | — | — | — |
| SL-3096 |  | miss | — | — | — | — |
| SL-3097 |  | miss | — | — | — | — |
| SL-3098 |  | miss | — | — | — | — |
| SL-3099 |  | miss | — | — | — | — |
| SL-3100 |  | miss | — | — | — | — |
| SL-3101 |  | miss | — | — | — | — |
| SL-3102 |  | miss | — | — | — | — |
| SL-3103 |  | miss | — | — | — | — |
| SL-3104 |  | miss | — | — | — | — |
| SL-3105 |  | hit | ML-KEM | — | yes | — |
| SL-3106 |  | hit | ML-KEM | — | yes | — |
| SL-3107 |  | miss | — | — | — | — |
| SL-3108 |  | miss | — | — | — | — |
| SL-3109 |  | miss | — | — | — | — |
| SL-3110 |  | miss | — | — | — | — |
| SL-3111 |  | miss | — | — | — | — |
| SL-3112 |  | miss | — | — | — | — |
| SL-3113 |  | miss | — | — | — | — |
| SL-3114 |  | miss | — | — | — | — |
| SL-3115 |  | miss | — | — | — | — |
| SL-3116 |  | miss | — | — | — | — |
| SL-3117 |  | miss | — | — | — | — |
| SL-3118 | yes | false_alarm | RSA | — | — | — |
| SL-3119 | yes | ok | — | — | — | — |
| SL-3120 |  | hit | RSA | — | no | no |
| SL-3121 |  | hit | RSA | — | no | no |
| SL-3122 |  | hit | RSA | — | no | no |
| SL-3123 |  | miss | — | — | — | — |
| SL-3124 |  | miss | — | — | — | — |
| SL-3125 |  | parent_only | EC | — | — | — |
| SL-3126 |  | hit | ML-DSA | — | yes | — |
| SL-3127 |  | hit | SLH-DSA | — | yes | — |
| SL-3128 |  | hit | ML-KEM | — | yes | — |
| SL-3129 |  | miss | — | — | — | — |
| SL-3130 |  | parent_only | EC | — | — | — |
| SL-3131 | yes | ok | — | — | — | — |
| SL-3132 |  | miss | — | — | — | — |
| SL-3133 |  | miss | — | — | — | — |
| SL-3134 |  | hit | RSA | — | — | no |
| SL-3135 |  | hit | RSA | — | — | no |
| SL-3136 |  | hit | EC | — | — | no |
| SL-3137 |  | hit | EC | — | — | no |
| SL-3138 |  | hit | EC | — | — | no |
| SL-3139 |  | miss | — | — | — | — |
| SL-3140 |  | miss | — | — | — | — |
| SL-3141 |  | miss | — | — | — | — |
| SL-3142 |  | miss | — | — | — | — |
| SL-3143 |  | miss | — | — | — | — |
| SL-3144 |  | miss | — | — | — | — |
| SL-3145 |  | miss | — | — | — | — |
| SL-3146 |  | miss | — | — | — | — |
| SL-3147 |  | miss | — | — | — | — |
| SL-3148 |  | miss | — | — | — | — |
| SL-3149 |  | miss | — | — | — | — |
| SL-3150 |  | hit | RSA | — | — | no |
| SL-3151 |  | hit | RSA | — | — | no |
| SL-3152 |  | hit | EC | — | — | no |
| SL-3153 |  | hit | EC | — | — | no |
| SL-3154 |  | hit | EC | — | — | no |
| SL-3155 |  | miss | — | — | — | — |
| SL-3156 | yes | false_alarm | RSA | — | — | — |
| SL-3157 |  | hit | RSA | — | — | no |
| SL-3158 |  | hit | RSA | — | — | no |
| SL-3159 |  | miss | — | — | — | — |
| SL-3160 |  | miss | — | — | — | — |
| SL-3161 |  | hit | EC | — | — | no |
| SL-3162 |  | miss | — | — | — | — |
| SL-3163 |  | hit | EC | — | — | no |
| SL-3164 |  | hit | EC | — | — | no |
| SL-3165 | yes | false_alarm | RSA | — | — | — |
| SL-3166 |  | hit | RSA | — | — | no |
| SL-3167 |  | parent_only | EC | — | — | — |
| SL-3168 |  | parent_only | EC | — | — | — |
| SL-3169 |  | miss | — | — | — | — |
| SL-3170 |  | miss | — | — | — | — |
| SL-3171 |  | miss | — | — | — | — |
| SL-3172 |  | miss | — | — | — | — |
| SL-3173 |  | miss | — | — | — | — |
| SL-3174 |  | miss | — | — | — | — |
| SL-3175 | yes | false_alarm | EC | — | — | — |
| SL-3176 |  | parent_only | EC | — | — | — |
| SL-3177 |  | parent_only | EC | — | — | — |
| SL-3178 |  | parent_only | EC | — | — | — |
| SL-3179 |  | parent_only | EC | — | — | — |
| SL-3180 |  | hit | RSA | — | — | no |
| SL-3181 |  | hit | RSA | — | — | no |
| SL-3182 |  | hit | RSA | — | — | no |
| SL-3183 |  | hit | ML-DSA | — | yes | — |
| SL-3184 |  | hit | ML-DSA | — | yes | — |
| SL-3185 |  | hit | SLH-DSA | — | yes | — |
| SL-3186 |  | hit | SLH-DSA | — | yes | — |
| SL-3187 |  | hit | EC, ML-DSA | — | yes | — |
| SL-3188 |  | parent_only | EC | — | — | — |
| SL-3189 |  | hit | RSA | — | — | no |
| SL-3190 |  | hit | RSA | — | — | no |
| SL-3191 |  | miss | — | — | — | — |
| SL-3192 |  | miss | — | — | — | — |
| SL-3193 |  | miss | — | — | — | — |
| SL-3194 |  | parent_only | EC | — | — | — |
| SL-3195 |  | hit | ML-DSA | — | yes | — |
| SL-3196 |  | miss | — | — | — | — |
| SL-3197 |  | hit | ML-DSA | — | yes | — |
| SL-3198 |  | hit | RSA | — | no | no |
| SL-3199 |  | parent_only | EC | — | — | — |
| SL-3200 |  | parent_only | EC | — | — | — |
| SL-3201 |  | parent_only | EC | — | — | — |
| SL-3202 |  | parent_only | EC | — | — | — |
| SL-3203 |  | miss | — | — | — | — |
| SL-3204 | yes | ok | — | — | — | — |
| SL-3205 |  | hit | RSA | — | — | no |
| SL-3206 |  | parent_only | EC | — | — | — |
| SL-3207 |  | parent_only | EC | — | — | — |
| SL-3208 |  | miss | — | — | — | — |
| SL-3209 |  | miss | — | — | — | — |
| SL-3210 |  | miss | — | — | — | — |
| SL-3211 |  | miss | — | — | — | — |
| SL-3212 |  | miss | — | — | — | — |
| SL-3213 |  | miss | — | — | — | — |
| SL-3214 |  | miss | — | — | — | — |
| SL-3215 |  | miss | — | — | — | — |
| SL-3216 |  | miss | — | — | — | — |
| SL-3217 |  | miss | — | — | — | — |
| SL-3218 |  | miss | — | — | — | — |
| SL-3219 | yes | ok | — | — | — | — |
| SL-3220 | yes | false_alarm | EC | — | — | — |
| SL-3221 | yes | false_alarm | RSA | — | — | — |
| SL-3222 | yes | ok | — | — | — | — |
| SL-3223 | yes | false_alarm | RSA | — | — | — |
| SL-3224 | yes | ok | — | — | — | — |
| SL-3500 |  | miss | — | — | — | — |
| SL-3501 |  | miss | — | — | — | — |
| SL-3502 |  | miss | — | — | — | — |
| SL-3503 |  | miss | — | — | — | — |
| SL-3504 |  | miss | — | — | — | — |
| SL-3505 |  | miss | — | — | — | — |
| SL-3506 |  | miss | — | — | — | — |
| SL-3507 |  | miss | — | — | — | — |
| SL-3508 |  | miss | — | — | — | — |
| SL-3509 |  | miss | — | — | — | — |
| SL-3510 |  | miss | — | — | — | — |
| SL-3511 |  | miss | — | — | — | — |
| SL-3512 |  | miss | — | — | — | — |
| SL-3513 |  | miss | — | — | — | — |
| SL-3514 |  | miss | — | — | — | — |
| SL-3515 |  | miss | — | — | — | — |
| SL-3516 |  | miss | — | — | — | — |
| SL-3517 |  | miss | — | — | — | — |
| SL-3518 |  | miss | — | — | — | — |
| SL-3519 |  | miss | — | — | — | — |
| SL-3520 |  | miss | — | — | — | — |
| SL-3521 |  | miss | — | — | — | — |
| SL-3522 |  | miss | — | — | — | — |
| SL-3523 |  | miss | — | — | — | — |
| SL-3524 |  | miss | — | — | — | — |
| SL-3525 |  | miss | — | — | — | — |
| SL-3526 |  | miss | — | — | — | — |
| SL-3527 |  | miss | — | — | — | — |
| SL-3528 |  | miss | — | — | — | — |
| SL-3529 |  | miss | — | — | — | — |
| SL-3530 |  | miss | — | — | — | — |
| SL-3531 |  | miss | — | — | — | — |
| SL-3532 |  | miss | — | — | — | — |
| SL-3533 |  | miss | — | — | — | — |
| SL-3534 |  | miss | — | — | — | — |
| SL-3535 |  | miss | — | — | — | — |
| SL-3536 |  | miss | — | — | — | — |
| SL-3537 |  | miss | — | — | — | — |
| SL-3538 |  | miss | — | — | — | — |
| SL-3539 |  | miss | — | — | — | — |
| SL-3540 |  | miss | — | — | — | — |
| SL-3541 |  | miss | — | — | — | — |
| SL-3542 |  | miss | — | — | — | — |
| SL-3543 |  | miss | — | — | — | — |
| SL-3544 |  | miss | — | — | — | — |
| SL-3545 |  | miss | — | — | — | — |
| SL-3546 |  | miss | — | — | — | — |
| SL-3547 |  | miss | — | — | — | — |
| SL-3548 |  | miss | — | — | — | — |
| SL-3549 |  | miss | — | — | — | — |
| SL-3550 |  | miss | — | — | — | — |
| SL-3551 |  | miss | — | — | — | — |
| SL-3552 |  | miss | — | — | — | — |
| SL-3553 | yes | ok | — | — | — | — |
| SL-3554 | yes | ok | — | — | — | — |
| SL-3555 | yes | ok | — | — | — | — |
| SL-3556 | yes | ok | — | — | — | — |
| SL-3557 |  | hit | RSA | — | — | no |
| SL-3558 |  | hit | EC | — | — | no |
| SL-3559 |  | hit | RSA | — | no | — |
| SL-3560 | yes | ok | — | — | — | — |
| SL-3561 | yes | false_alarm | EC | — | — | — |
| SL-3562 |  | hit | RSA | — | — | — |
| SL-3563 |  | hit | RSA | — | — | no |
| SL-3564 |  | miss | — | — | — | — |
| SL-3565 |  | hit | EC | — | — | no |
| SL-3566 |  | miss | — | — | — | — |
| SL-3567 |  | miss | — | — | — | — |
| SL-3568 |  | miss | — | — | — | — |
| SL-3569 |  | parent_only | EC | — | — | — |
| SL-3570 |  | miss | — | — | — | — |
| SL-3571 |  | miss | — | — | — | — |
| SL-3572 |  | miss | — | — | — | — |
| SL-3573 |  | miss | — | — | — | — |
| SL-3574 |  | miss | — | — | — | — |
| SL-3575 |  | hit | ML-KEM | — | yes | — |
| SL-3576 |  | hit | ML-KEM | — | yes | — |
| SL-3577 |  | hit | ML-DSA | — | yes | — |
| SL-3578 |  | hit | ML-DSA | — | yes | — |
| SL-3579 | yes | ok | — | — | — | — |
| SL-3580 | yes | false_alarm | ML-DSA | — | — | — |
| SL-3581 |  | parent_only | EC | — | — | — |
| SL-3582 |  | miss | — | — | — | — |
| SL-3583 |  | miss | — | — | — | — |
| SL-3584 |  | miss | — | — | — | — |
| SL-3585 | yes | false_alarm | EC | — | — | — |
| SL-3586 | yes | false_alarm | RSA | — | — | — |
| SL-3587 | yes | ok | — | — | — | — |
| SL-3588 | yes | false_alarm | RSA | — | — | — |
| SL-3589 |  | parent_only | EC | — | — | — |
| SL-3590 |  | parent_only | EC | — | — | — |
| SL-3591 |  | parent_only | EC | — | — | — |
| SL-3592 |  | hit | RSA | — | no | no |
| SL-3593 |  | parent_only | EC | — | — | — |
| SL-3594 |  | parent_only | EC | — | — | — |
| SL-3595 | yes | ok | — | — | — | — |
| SL-3596 |  | hit | RSA | — | — | — |
| SL-3597 |  | hit | RSA | — | — | — |
| SL-3598 |  | hit | DSA | — | yes | — |
| SL-3599 |  | hit | DSA | — | yes | — |
| SL-3600 |  | hit | DSA | — | yes | — |
| SL-3601 |  | miss | — | — | — | — |
| SL-3602 |  | miss | — | — | — | — |
| SL-3603 |  | parent_only | EC | — | — | — |
| SL-3604 |  | miss | — | — | — | — |
| SL-3605 | yes | ok | — | — | — | — |
| SL-3606 |  | hit | RSA | — | — | — |
| SL-3607 |  | hit | EC | — | — | no |
| SL-3608 |  | hit | EC | — | — | no |
| SL-3609 |  | parent_only | EC | — | — | — |
| SL-3610 |  | miss | — | — | — | — |
| SL-3611 |  | miss | — | — | — | — |
| SL-3612 |  | miss | — | — | — | — |
| SL-3613 |  | hit | ML-DSA | — | yes | — |
| SL-3614 |  | hit | ML-DSA | — | yes | — |
| SL-3615 |  | hit | ML-DSA | — | yes | — |
| SL-3616 |  | miss | — | — | — | — |
| SL-3617 |  | hit | RSA | — | no | — |
| SL-3618 |  | parent_only | EC | — | — | — |
| SL-3619 |  | parent_only | EC | — | — | — |
| SL-3620 |  | parent_only | EC | — | — | — |
| SL-3621 |  | parent_only | EC | — | — | — |
| SL-3622 |  | parent_only | EC | — | — | — |
| SL-3623 |  | parent_only | EC | — | — | — |
| SL-3624 | yes | false_alarm | RSA | — | — | — |
| SL-3625 |  | parent_only | EC | — | — | — |
| SL-3626 |  | parent_only | EC | — | — | — |
| SL-3627 | yes | false_alarm | RSA | — | — | — |
| SL-3628 |  | miss | — | — | — | — |
| SL-3629 |  | miss | — | — | — | — |
| SL-3630 |  | hit | EC | — | — | no |
| SL-3631 |  | miss | — | — | — | — |
| SL-3632 |  | parent_only | EC | — | — | — |
| SL-3633 |  | miss | — | — | — | — |
| SL-3634 |  | hit | ML-DSA | — | yes | — |
| SL-3635 |  | hit | ML-KEM | — | yes | — |
| SL-3636 | yes | false_alarm | RSA | — | — | — |
| SL-4000 |  | hit | MD5 | — | yes | — |
| SL-4001 |  | hit | SHA-1 | — | yes | — |
| SL-4002 |  | hit | MD5 | — | yes | — |
| SL-4003 |  | hit | SHA-1 | — | yes | — |
| SL-4004 |  | miss | — | — | — | — |
| SL-4005 |  | hit | MD5 | — | yes | — |
| SL-4006 |  | hit | SHA-1 | — | yes | — |
| SL-4007 |  | hit | SHA-1 | — | yes | — |
| SL-4008 |  | hit | MD5 | — | yes | — |
| SL-4009 |  | hit | 3DES | — | yes | — |
| SL-4010 |  | hit | RC4 | — | yes | — |
| SL-4011 |  | hit | 3DES | — | yes | — |
| SL-4012 |  | hit | RC4 | — | yes | — |
| SL-4013 |  | hit | MD5 | — | yes | — |
| SL-4014 |  | hit | SHA-1 | — | yes | — |
| SL-4015 |  | miss | — | — | — | — |
| SL-4016 |  | miss | — | — | — | — |
| SL-4017 |  | hit | DES | — | yes | — |
| SL-4018 |  | miss | — | — | — | — |
| SL-4019 |  | hit | RC4 | — | yes | — |
| SL-4020 |  | hit | MD5 | — | yes | — |
| SL-4021 |  | hit | SHA-1 | — | yes | — |
| SL-4022 |  | miss | — | — | — | — |
| SL-4023 |  | hit | SHA-1 | — | yes | — |
| SL-4024 |  | wrong_family | DES | — | — | — |
| SL-4025 |  | wrong_family | DES | — | — | — |
| SL-4026 |  | wrong_family | DES | — | — | — |
| SL-4027 |  | miss | — | — | — | — |
| SL-4028 |  | miss | — | — | — | — |
| SL-4029 |  | hit | RC4 | — | yes | — |
| SL-4030 |  | hit | RC4 | — | yes | — |
| SL-4031 |  | miss | — | — | — | — |
| SL-4032 |  | wrong_family | DES | — | — | — |
| SL-4033 |  | miss | — | — | — | — |
| SL-4034 |  | hit | RC4 | — | yes | — |
| SL-4035 |  | wrong_family | DES | — | — | — |
| SL-4036 |  | hit | 3DES | — | yes | — |
| SL-4037 |  | miss | — | — | — | — |
| SL-4038 |  | miss | — | — | — | — |
| SL-4039 |  | miss | — | — | — | — |
| SL-4040 |  | miss | — | — | — | — |
| SL-4041 |  | hit | MD5 | — | yes | — |
| SL-4042 |  | hit | SHA-1 | — | yes | — |
| SL-4043 |  | wrong_family | DES | — | — | — |
| SL-4044 |  | hit | RC4 | — | yes | — |
| SL-4045 |  | hit | MD5 | — | yes | — |
| SL-4046 |  | hit | MD5 | — | yes | — |
| SL-4047 |  | hit | SHA-1 | — | yes | — |
| SL-4048 |  | hit | SHA-1 | — | yes | — |
| SL-4049 |  | hit | 3DES | — | yes | — |
| SL-4050 |  | hit | DES | — | yes | — |
| SL-4051 |  | hit | RC4 | — | yes | — |
| SL-4052 |  | hit | MD5 | — | yes | — |
| SL-4053 |  | hit | SHA-1 | — | yes | — |
| SL-4054 |  | hit | 3DES | — | yes | — |
| SL-4055 |  | miss | — | — | — | — |
| SL-4056 |  | miss | — | — | — | — |
| SL-4057 |  | hit | MD5 | — | yes | — |
| SL-4058 |  | hit | SHA-1 | — | yes | — |
| SL-4059 |  | miss | — | — | — | — |
| SL-4060 |  | miss | — | — | — | — |
| SL-4061 |  | miss | — | — | — | — |
| SL-4062 |  | miss | — | — | — | — |
| SL-4063 |  | miss | — | — | — | — |
| SL-4064 |  | miss | — | — | — | — |
| SL-4065 |  | hit | SHA-1 | — | yes | — |
| SL-4066 |  | hit | MD5 | — | yes | — |
| SL-4067 |  | hit | MD5 | — | yes | — |
| SL-4068 |  | hit | SHA-1 | — | yes | — |
| SL-4069 |  | miss | — | — | — | — |
| SL-4070 |  | hit | SHA-1 | — | yes | — |
| SL-4071 |  | hit | MD5 | — | yes | — |
| SL-4072 |  | wrong_family | DES | — | — | — |
| SL-4073 |  | hit | DES | — | yes | — |
| SL-4074 |  | hit | RC4 | — | yes | — |
| SL-4075 |  | miss | — | — | — | — |
| SL-4076 |  | miss | — | — | — | — |
| SL-4077 |  | hit | SHA-1 | — | yes | — |
| SL-4078 |  | miss | — | — | — | — |
| SL-4079 |  | miss | — | — | — | — |
| SL-4080 |  | miss | — | — | — | — |
| SL-4081 |  | miss | — | — | — | — |
| SL-4082 |  | miss | — | — | — | — |
| SL-4083 |  | miss | — | — | — | — |
| SL-4084 |  | miss | — | — | — | — |
| SL-4085 |  | miss | — | — | — | — |
| SL-4086 |  | miss | — | — | — | — |
| SL-4087 |  | hit | MD5 | — | yes | — |
| SL-4088 |  | hit | SHA-1 | — | yes | — |
| SL-4089 |  | miss | — | — | — | — |
| SL-4090 |  | miss | — | — | — | — |
| SL-4091 |  | hit | MD5 | — | yes | — |
| SL-4092 |  | miss | — | — | — | — |
| SL-4093 |  | miss | — | — | — | — |
| SL-4094 |  | hit | SHA-1 | — | yes | — |
| SL-4095 |  | hit | MD5 | — | yes | — |
| SL-4096 |  | hit | SHA-1 | — | yes | — |
| SL-4097 |  | miss | — | — | — | — |
| SL-4098 |  | miss | — | — | — | — |
| SL-4099 |  | hit | MD5 | — | yes | — |
| SL-4100 |  | hit | SHA-1 | — | yes | — |
| SL-4101 |  | miss | — | — | — | — |
| SL-4102 |  | miss | — | — | — | — |
| SL-4103 |  | hit | DES | — | yes | — |
| SL-4104 |  | hit | RC4 | — | yes | — |
| SL-4105 |  | hit | MD5 | — | yes | — |
| SL-4106 |  | hit | SHA-1 | — | yes | — |
| SL-4107 |  | hit | SHA-1 | — | yes | — |
| SL-4108 |  | hit | MD5 | — | yes | — |
| SL-4109 |  | miss | — | — | — | — |
| SL-4110 |  | hit | RC4 | — | yes | — |
| SL-4111 |  | hit | MD5 | — | yes | — |
| SL-4112 |  | hit | SHA-1 | — | yes | — |
| SL-4113 |  | miss | — | — | — | — |
| SL-4114 |  | miss | — | — | — | — |
| SL-4115 |  | miss | — | — | — | — |
| SL-4116 |  | miss | — | — | — | — |
| SL-4117 |  | hit | RC4 | — | yes | — |
| SL-4118 |  | hit | SHA-1 | — | yes | — |
| SL-4119 |  | hit | MD5 | — | yes | — |
| SL-4120 |  | hit | MD5 | — | yes | — |
| SL-4121 |  | hit | SHA-1 | — | yes | — |
| SL-4122 |  | hit | SHA-1 | — | yes | — |
| SL-4123 | yes | ok | — | — | — | — |
| SL-4124 | yes | false_alarm | SHA-1 | — | — | — |
| SL-4125 | yes | false_alarm | MD5 | — | — | — |
| SL-4126 | yes | ok | — | — | — | — |
| SL-4127 | yes | ok | — | — | — | — |
| SL-4128 | yes | ok | — | — | — | — |
| SL-4129 | yes | false_alarm | RC4 | — | — | — |
| SL-4130 | yes | ok | — | — | — | — |
| SL-4131 | yes | ok | — | — | — | — |
| SL-4132 | yes | ok | — | — | — | — |
| SL-4133 | yes | ok | — | — | — | — |
| SL-4134 | yes | ok | — | — | — | — |
| SL-4135 | yes | ok | — | — | — | — |
| SL-4136 | yes | ok | — | — | — | — |
| SL-4500 |  | miss | — | — | — | — |
| SL-4501 |  | miss | — | — | — | — |
| SL-4502 |  | miss | — | — | — | — |
| SL-4503 |  | miss | — | — | — | — |
| SL-4504 |  | miss | — | — | — | — |
| SL-4505 |  | miss | — | — | — | — |
| SL-4506 |  | miss | — | — | — | — |
| SL-4507 |  | miss | — | — | — | — |
| SL-4508 |  | miss | — | — | — | — |
| SL-4509 |  | miss | — | — | — | — |
| SL-4510 |  | miss | — | — | — | — |
| SL-4511 |  | miss | — | — | — | — |
| SL-4512 |  | miss | — | — | — | — |
| SL-4513 |  | miss | — | — | — | — |
| SL-4514 |  | miss | — | — | — | — |
| SL-4515 |  | miss | — | — | — | — |
| SL-4516 |  | miss | — | — | — | — |
| SL-4517 |  | miss | — | — | — | — |
| SL-4518 |  | miss | — | — | — | — |
| SL-4519 |  | miss | — | — | — | — |
| SL-4520 |  | miss | — | — | — | — |
| SL-4521 |  | miss | — | — | — | — |
| SL-4522 |  | miss | — | — | — | — |
| SL-4523 |  | miss | — | — | — | — |
| SL-4524 |  | miss | — | — | — | — |
| SL-4525 |  | miss | — | — | — | — |
| SL-4526 |  | miss | — | — | — | — |
| SL-4527 |  | miss | — | — | — | — |
| SL-4528 |  | miss | — | — | — | — |
| SL-4529 |  | miss | — | — | — | — |
| SL-4530 |  | miss | — | — | — | — |
| SL-4531 |  | miss | — | — | — | — |
| SL-4532 |  | miss | — | — | — | — |
| SL-4533 |  | miss | — | — | — | — |
| SL-4534 |  | miss | — | — | — | — |
| SL-4535 |  | miss | — | — | — | — |
| SL-4536 |  | miss | — | — | — | — |
| SL-4537 |  | miss | — | — | — | — |
| SL-4538 |  | miss | — | — | — | — |
| SL-4539 |  | miss | — | — | — | — |
| SL-4540 |  | miss | — | — | — | — |
| SL-4541 |  | miss | — | — | — | — |
| SL-4542 |  | miss | — | — | — | — |
| SL-4543 |  | miss | — | — | — | — |
| SL-4544 |  | miss | — | — | — | — |
| SL-4545 |  | miss | — | — | — | — |
| SL-4546 |  | miss | — | — | — | — |
| SL-4547 |  | miss | — | — | — | — |
| SL-4548 |  | miss | — | — | — | — |
| SL-4549 |  | miss | — | — | — | — |
| SL-4550 |  | miss | — | — | — | — |
| SL-4551 |  | miss | — | — | — | — |
| SL-4552 |  | miss | — | — | — | — |
| SL-4553 |  | miss | — | — | — | — |
| SL-4554 |  | miss | — | — | — | — |
| SL-4555 |  | miss | — | — | — | — |
| SL-4556 |  | miss | — | — | — | — |
| SL-4557 |  | miss | — | — | — | — |
| SL-4558 |  | miss | — | — | — | — |
| SL-4559 |  | miss | — | — | — | — |
| SL-4560 |  | miss | — | — | — | — |
| SL-4561 | yes | ok | — | — | — | — |
| SL-4562 |  | miss | — | — | — | — |
| SL-4563 |  | wrong_family | DH, RSA | — | — | — |
| SL-4564 |  | wrong_family | DH, EC | — | — | — |
| SL-4565 |  | wrong_family | DH, RSA | — | — | — |
| SL-4566 |  | hit | RC4 | — | yes | — |
| SL-4567 |  | hit | MD5, RC4 | — | yes | — |
| SL-4568 |  | hit | DH, RC4, RSA | — | yes | — |
| SL-4569 |  | hit | DH, EC, RC4 | — | yes | — |
| SL-4570 |  | hit | MD5 | — | no | — |
| SL-4571 |  | miss | — | — | — | — |
| SL-4572 |  | wrong_family | DH | — | — | — |
| SL-4573 |  | hit | RC4 | — | yes | — |
| SL-4574 |  | hit | MD5, RC4 | — | yes | — |
| SL-4575 |  | wrong_family | DH, RSA | — | — | — |
| SL-4576 |  | hit | MD5, RC4 | — | yes | — |
| SL-4577 | yes | false_alarm | MD5 | — | — | — |
| SL-4578 | yes | false_alarm | 3DES | — | — | — |
| SL-4579 | yes | false_alarm | RC4 | — | — | — |
| SL-4580 | yes | ok | — | — | — | — |
| SL-4581 |  | hit | 3DES | — | yes | — |
| SL-4582 |  | hit | MD5 | — | no | — |
| SL-4583 |  | hit | MD5 | — | no | — |
| SL-4584 |  | hit | MD5 | — | no | — |
| SL-4585 |  | hit | MD5 | — | no | — |
| SL-4586 |  | hit | SHA-1 | — | no | — |
| SL-4587 |  | hit | SHA-1 | — | no | — |
| SL-4588 |  | hit | SHA-1 | — | no | — |
| SL-4589 |  | hit | SHA-1 | — | no | — |
| SL-4590 |  | hit | DH, SHA-1 | — | yes | no |
| SL-4591 |  | hit | DH, SHA-1 | — | yes | — |
| SL-4592 |  | hit | DH, SHA-1 | — | yes | — |
| SL-4593 | yes | false_alarm | 3DES | — | — | — |
| SL-4594 | yes | false_alarm | SHA-1 | — | — | — |
| SL-4595 | yes | false_alarm | DH, SHA-1 | — | — | — |
| SL-4596 | yes | false_alarm | MD5 | — | — | — |
| SL-4597 |  | hit | 3DES | — | yes | — |
| SL-4598 |  | hit | 3DES | — | yes | — |
| SL-4599 |  | hit | RC4 | — | yes | — |
| SL-4600 |  | miss | — | — | — | — |
| SL-4601 |  | miss | — | — | — | — |
| SL-4602 |  | hit | MD5 | — | no | — |
| SL-4603 |  | hit | MD5 | — | no | — |
| SL-4604 |  | hit | SHA-1 | — | no | — |
| SL-4605 |  | hit | SHA-1 | — | no | — |
| SL-4606 |  | hit | DH, SHA-1 | — | yes | — |
| SL-4607 |  | hit | DH, SHA-1 | — | yes | — |
| SL-4608 |  | hit | DH, SHA-1 | — | yes | — |
| SL-4609 |  | hit | RSA | — | — | no |
| SL-4610 |  | miss | — | — | — | — |
| SL-4611 |  | miss | — | — | — | — |
| SL-4612 |  | miss | — | — | — | — |
| SL-4613 |  | hit | RSA | — | — | no |
| SL-4614 |  | hit | RSA | — | — | no |
| SL-4615 |  | miss | — | — | — | — |
| SL-4616 |  | miss | — | — | — | — |
| SL-4617 |  | miss | — | — | — | — |
| SL-4618 |  | miss | — | — | — | — |
| SL-4619 |  | miss | — | — | — | — |
| SL-4620 |  | miss | — | — | — | — |
| SL-4621 | yes | ok | — | — | — | — |
| SL-4622 |  | hit | SHA-1 | — | yes | — |
| SL-4623 |  | hit | MD5 | — | yes | — |
| SL-4624 |  | hit | SHA-1 | — | yes | — |
| SL-4625 |  | hit | MD5 | — | yes | — |
| SL-4626 |  | miss | — | — | — | — |
| SL-4627 | yes | false_alarm | MD5 | — | — | — |
| SL-4628 |  | hit | RSA | — | — | no |
| SL-4629 |  | wrong_family | RSA | — | — | — |
| SL-4630 |  | hit | RSA | — | — | no |
| SL-4631 |  | hit | DSA | — | yes | no |
| SL-4632 |  | miss | — | — | — | — |
| SL-4633 | yes | false_alarm | RC4 | — | — | — |
| SL-4634 | yes | ok | — | — | — | — |
| SL-4635 | yes | ok | — | — | — | — |
| SL-4636 | yes | ok | — | — | — | — |
| SL-4637 | yes | false_alarm | SHA-1 | — | — | — |
| SL-4638 |  | hit | RSA | — | — | no |
| SL-4639 |  | hit | RSA | — | — | no |
| SL-4640 |  | miss | — | — | — | — |
| SL-4641 |  | miss | — | — | — | — |
| SL-4642 |  | miss | — | — | — | — |
| SL-4643 |  | hit | RSA | — | — | no |
| SL-4644 |  | miss | — | — | — | — |
| SL-4645 |  | hit | RSA | — | — | no |
| SL-4646 |  | parent_only | EC | — | — | — |
| SL-4647 |  | parent_only | EC | — | — | — |
| SL-4648 |  | parent_only | EC | — | — | — |
| SL-4649 |  | hit | RSA | — | — | no |
| SL-4650 |  | miss | — | — | — | — |
| SL-4651 |  | miss | — | — | — | — |
| SL-4652 |  | miss | — | — | — | — |
| SL-4653 |  | miss | — | — | — | — |
| SL-4654 |  | miss | — | — | — | — |
| SL-4655 |  | hit | 3DES | — | yes | — |
| SL-4656 |  | hit | MD5 | — | no | — |
| SL-4657 |  | miss | — | — | — | — |
| SL-4658 |  | hit | 3DES | — | yes | — |
| SL-4659 |  | hit | MD5 | — | no | — |
| SL-4660 | yes | false_alarm | 3DES | — | — | — |
| SL-4661 |  | miss | — | — | — | — |
| SL-4662 |  | miss | — | — | — | — |
| SL-4663 |  | miss | — | — | — | — |
| SL-4664 |  | miss | — | — | — | — |
| SL-4665 |  | miss | — | — | — | — |
| SL-4666 |  | miss | — | — | — | — |
| SL-4667 |  | miss | — | — | — | — |
| SL-4668 |  | miss | — | — | — | — |
| SL-4669 |  | miss | — | — | — | — |
| SL-5000 |  | miss; fixed file: ok | — | — | — | — |
| SL-5001 |  | miss; fixed file: ok | — | — | — | — |
| SL-5002 |  | miss; fixed file: ok | — | — | — | — |
| SL-5003 |  | miss; fixed file: ok | — | — | — | — |
| SL-5004 |  | miss; fixed file: ok | — | — | — | — |
| SL-5005 |  | miss; fixed file: ok | — | — | — | — |
| SL-5006 |  | miss; fixed file: ok | — | — | — | — |
| SL-5007 |  | miss; fixed file: ok | — | — | — | — |
| SL-5008 |  | miss; fixed file: ok | — | — | — | — |
| SL-5009 |  | miss; fixed file: ok | — | — | — | — |
| SL-5010 |  | miss; fixed file: ok | — | — | — | — |
| SL-5011 |  | miss; fixed file: ok | — | — | — | — |
| SL-5012 |  | miss; fixed file: ok | — | — | — | — |
| SL-5013 |  | miss; fixed file: ok | — | — | — | — |
| SL-5014 |  | miss; fixed file: ok | — | — | — | — |
| SL-5015 |  | miss; fixed file: ok | — | — | — | — |
| SL-5016 |  | miss; fixed file: ok | — | — | — | — |
| SL-5017 |  | miss; fixed file: ok | — | — | — | — |
| SL-5018 |  | miss; fixed file: ok | — | — | — | — |
| SL-5019 |  | miss; fixed file: ok | — | — | — | — |
| SL-5020 |  | miss; fixed file: ok | — | — | — | — |
| SL-5021 |  | miss; fixed file: ok | — | — | — | — |
| SL-5022 |  | miss; fixed file: ok | — | — | — | — |
| SL-5023 |  | miss; fixed file: ok | — | — | — | — |
| SL-5024 |  | miss; fixed file: ok | — | — | — | — |
| SL-5025 |  | miss; fixed file: ok | — | — | — | — |
| SL-5026 |  | miss; fixed file: ok | — | — | — | — |
| SL-5027 |  | miss; fixed file: ok | — | — | — | — |
| SL-5028 |  | miss; fixed file: ok | — | — | — | — |
| SL-5029 |  | miss; fixed file: ok | — | — | — | — |
| SL-5030 |  | miss; fixed file: ok | — | — | — | — |
| SL-5031 |  | miss; fixed file: ok | — | — | — | — |
| SL-5032 |  | miss; fixed file: ok | — | — | — | — |
| SL-5033 |  | miss; fixed file: ok | — | — | — | — |
| SL-5034 |  | miss; fixed file: ok | — | — | — | — |
| SL-5035 |  | miss; fixed file: ok | — | — | — | — |
| SL-5036 |  | miss; fixed file: ok | — | — | — | — |
| SL-5037 |  | miss; fixed file: ok | — | — | — | — |
| SL-5038 |  | miss; fixed file: ok | — | — | — | — |
| SL-5039 |  | miss; fixed file: ok | — | — | — | — |
| SL-5040 |  | miss; fixed file: ok | — | — | — | — |
| SL-5041 |  | miss; fixed file: ok | — | — | — | — |
| SL-5042 |  | miss; fixed file: ok | — | — | — | — |
| SL-5043 |  | miss; fixed file: ok | — | — | — | — |
| SL-5044 |  | miss; fixed file: ok | — | — | — | — |
| SL-5045 |  | miss; fixed file: ok | — | — | — | — |
| SL-5046 |  | miss; fixed file: ok | — | — | — | — |
| SL-5047 |  | miss; fixed file: ok | — | — | — | — |
| SL-5048 |  | miss; fixed file: ok | — | — | — | — |
| SL-5049 |  | miss; fixed file: ok | — | — | — | — |
| SL-5050 |  | miss; fixed file: ok | — | — | — | — |
| SL-5051 |  | miss; fixed file: ok | — | — | — | — |
| SL-5052 |  | miss; fixed file: ok | — | — | — | — |
| SL-5053 |  | miss; fixed file: ok | — | — | — | — |
| SL-5054 |  | miss; fixed file: ok | — | — | — | — |
| SL-5055 |  | miss; fixed file: ok | — | — | — | — |
| SL-5056 |  | miss; fixed file: ok | — | — | — | — |
| SL-5057 |  | miss; fixed file: ok | — | — | — | — |
| SL-5058 |  | miss; fixed file: ok | — | — | — | — |
| SL-5059 |  | miss; fixed file: ok | — | — | — | — |
| SL-5060 |  | miss; fixed file: ok | — | — | — | — |
| SL-5061 |  | miss; fixed file: ok | — | — | — | — |
| SL-5062 |  | miss; fixed file: ok | — | — | — | — |
| SL-5063 |  | miss; fixed file: ok | — | — | — | — |
| SL-5064 |  | miss; fixed file: ok | — | — | — | — |
| SL-5065 |  | miss; fixed file: ok | — | — | — | — |
| SL-5066 |  | miss; fixed file: ok | — | — | — | — |
| SL-5067 |  | miss; fixed file: ok | — | — | — | — |
| SL-5068 |  | miss; fixed file: ok | — | — | — | — |
| SL-5069 |  | miss; fixed file: ok | — | — | — | — |
| SL-5070 |  | miss; fixed file: ok | — | — | — | — |
| SL-5071 |  | miss; fixed file: ok | — | — | — | — |
| SL-5072 |  | miss; fixed file: ok | — | — | — | — |
| SL-5073 |  | miss; fixed file: ok | — | — | — | — |
| SL-5074 |  | miss; fixed file: ok | — | — | — | — |
| SL-5075 |  | miss; fixed file: ok | — | — | — | — |
| SL-5076 |  | miss; fixed file: ok | — | — | — | — |
| SL-5077 |  | miss; fixed file: ok | — | — | — | — |
| SL-5078 |  | miss; fixed file: ok | — | — | — | — |
| SL-5079 |  | miss; fixed file: ok | — | — | — | — |
| SL-5080 |  | miss; fixed file: ok | — | — | — | — |
| SL-5081 |  | miss; fixed file: ok | — | — | — | — |
| SL-5082 |  | miss; fixed file: ok | — | — | — | — |
| SL-5083 |  | miss; fixed file: ok | — | — | — | — |
| SL-5084 | yes | ok | — | — | — | — |
| SL-5085 | yes | ok | — | — | — | — |
| SL-5086 | yes | ok | — | — | — | — |
| SL-5087 | yes | ok | — | — | — | — |
| SL-5088 | yes | ok | — | — | — | — |
| SL-5089 | yes | ok | — | — | — | — |
| SL-5090 | yes | ok | — | — | — | — |
| SL-5091 | yes | ok | — | — | — | — |
| SL-5092 | yes | ok | — | — | — | — |
| SL-5093 | yes | ok | — | — | — | — |
| SL-5094 | yes | ok | — | — | — | — |
| SL-5500 |  | miss; fixed file: ok | — | — | — | — |
| SL-5501 |  | miss; fixed file: ok | — | — | — | — |
| SL-5502 |  | miss; fixed file: ok | — | — | — | — |
| SL-5503 |  | miss; fixed file: ok | — | — | — | — |
| SL-5504 |  | miss; fixed file: ok | — | — | — | — |
| SL-5505 |  | miss; fixed file: ok | — | — | — | — |
| SL-5506 |  | miss; fixed file: ok | — | — | — | — |
| SL-5507 |  | miss; fixed file: ok | — | — | — | — |
| SL-5508 |  | miss; fixed file: ok | — | — | — | — |
| SL-5509 |  | miss; fixed file: ok | — | — | — | — |
| SL-5510 |  | miss; fixed file: ok | — | — | — | — |
| SL-5511 |  | miss; fixed file: ok | — | — | — | — |
| SL-5512 |  | miss; fixed file: ok | — | — | — | — |
| SL-5513 |  | miss; fixed file: ok | — | — | — | — |
| SL-5514 |  | miss; fixed file: ok | — | — | — | — |
| SL-5515 |  | miss; fixed file: ok | — | — | — | — |
| SL-5516 |  | miss; fixed file: ok | — | — | — | — |
| SL-5517 |  | miss; fixed file: ok | — | — | — | — |
| SL-5518 |  | miss; fixed file: ok | — | — | — | — |
| SL-5519 |  | miss; fixed file: ok | — | — | — | — |
| SL-5520 |  | miss; fixed file: ok | — | — | — | — |
| SL-5521 |  | miss; fixed file: ok | — | — | — | — |
| SL-5522 |  | miss; fixed file: ok | — | — | — | — |
| SL-5523 |  | miss; fixed file: ok | — | — | — | — |
| SL-5524 |  | miss; fixed file: ok | — | — | — | — |
| SL-5525 |  | miss; fixed file: ok | — | — | — | — |
| SL-5526 |  | miss; fixed file: ok | — | — | — | — |
| SL-5527 | yes | ok | — | — | — | — |
| SL-5528 | yes | ok | — | — | — | — |
| SL-5529 | yes | ok | — | — | — | — |
| SL-5530 | yes | ok | — | — | — | — |
| SL-5531 | yes | ok | — | — | — | — |
| SL-5532 | yes | ok | — | — | — | — |
| SL-5533 | yes | ok | — | — | — | — |
| SL-5534 |  | miss; fixed file: ok | — | — | — | — |
| SL-5535 |  | miss; fixed file: ok | — | — | — | — |
| SL-5536 |  | miss; fixed file: ok | — | — | — | — |
| SL-5537 |  | miss; fixed file: ok | — | — | — | — |
| SL-5538 |  | miss; fixed file: ok | — | — | — | — |
| SL-5539 |  | miss; fixed file: ok | — | — | — | — |
| SL-5540 |  | miss; fixed file: ok | — | — | — | — |
| SL-5541 |  | miss; fixed file: ok | — | — | — | — |
| SL-5542 |  | miss; fixed file: ok | — | — | — | — |
| SL-5543 |  | miss; fixed file: ok | — | — | — | — |
| SL-5544 |  | miss; fixed file: ok | — | — | — | — |
| SL-5545 |  | miss; fixed file: ok | — | — | — | — |
| SL-5546 |  | miss; fixed file: ok | — | — | — | — |
| SL-5547 |  | miss; fixed file: ok | — | — | — | — |
| SL-5548 |  | miss; fixed file: ok | — | — | — | — |
| SL-5549 |  | miss; fixed file: ok | — | — | — | — |
| SL-5550 |  | miss; fixed file: ok | — | — | — | — |
| SL-5551 |  | miss; fixed file: ok | — | — | — | — |
| SL-5552 |  | miss; fixed file: ok | — | — | — | — |
| SL-5553 |  | miss; fixed file: ok | — | — | — | — |
| SL-5554 |  | miss; fixed file: ok | — | — | — | — |
| SL-5555 |  | miss; fixed file: ok | — | — | — | — |
| SL-5556 |  | miss; fixed file: ok | — | — | — | — |
| SL-5557 |  | miss; fixed file: ok | — | — | — | — |
| SL-5558 | yes | ok | — | — | — | — |
| SL-5559 | yes | ok | — | — | — | — |
| SL-5560 | yes | ok | — | — | — | — |
| SL-6000 |  | miss; fixed file: ok | — | — | — | — |
| SL-6001 |  | miss; fixed file: ok | — | — | — | — |
| SL-6002 |  | miss; fixed file: ok | — | — | — | — |
| SL-6003 |  | miss; fixed file: ok | — | — | — | — |
| SL-6004 |  | miss; fixed file: ok | — | — | — | — |
| SL-6005 |  | miss; fixed file: ok | — | — | — | — |
| SL-6006 |  | miss; fixed file: ok | — | — | — | — |
| SL-6007 |  | miss; fixed file: ok | — | — | — | — |
| SL-6008 |  | miss; fixed file: ok | — | — | — | — |
| SL-6009 |  | miss; fixed file: ok | — | — | — | — |
| SL-6010 |  | miss; fixed file: ok | — | — | — | — |
| SL-6011 |  | miss; fixed file: ok | — | — | — | — |
| SL-6012 |  | miss; fixed file: ok | — | — | — | — |
| SL-6013 |  | miss; fixed file: ok | — | — | — | — |
| SL-6014 |  | miss; fixed file: ok | — | — | — | — |
| SL-6015 |  | miss; fixed file: ok | — | — | — | — |
| SL-6016 |  | miss; fixed file: ok | — | — | — | — |
| SL-6017 |  | miss; fixed file: ok | — | — | — | — |
| SL-6018 |  | miss; fixed file: ok | — | — | — | — |
| SL-6019 |  | miss; fixed file: ok | — | — | — | — |
| SL-6020 |  | miss; fixed file: ok | — | — | — | — |
| SL-6021 |  | miss; fixed file: ok | — | — | — | — |
| SL-6022 |  | miss; fixed file: ok | — | — | — | — |
| SL-6023 |  | miss; fixed file: ok | — | — | — | — |
| SL-6024 |  | miss; fixed file: ok | — | — | — | — |
| SL-6025 |  | miss; fixed file: ok | — | — | — | — |
| SL-6026 |  | miss; fixed file: ok | — | — | — | — |
| SL-6027 | yes | ok | — | — | — | — |
| SL-6028 | yes | ok | — | — | — | — |
| SL-6029 | yes | ok | — | — | — | — |
| SL-6030 | yes | ok | — | — | — | — |
| SL-6500 |  | parent_only | EC | — | — | — |
| SL-6501 |  | parent_only | EC | — | — | — |
| SL-6502 |  | parent_only | EC | — | — | — |
| SL-6503 |  | miss | — | — | — | — |
| SL-6504 | yes | false_alarm | ML-KEM | — | — | — |
| SL-6505 |  | hit | ML-KEM | — | yes | — |
| SL-6506 | yes | ok | — | — | — | — |
| SL-6507 |  | hit | ML-KEM | — | yes | — |
| SL-6508 | yes | ok | — | — | — | — |
| SL-6509 |  | hit | ML-KEM | — | yes | — |
| SL-6510 |  | hit | ML-KEM | — | yes | — |
| SL-6511 |  | hit | ML-KEM | — | yes | — |
| SL-6512 |  | hit | ML-KEM | — | yes | — |
| SL-6513 |  | hit | ML-KEM | — | yes | — |
| SL-6514 |  | hit | ML-KEM | — | yes | — |
| SL-6515 |  | hit | ML-DSA | — | yes | — |
| SL-6516 |  | hit | ML-DSA | — | yes | — |
| SL-6517 |  | hit | ML-KEM | — | yes | — |
| SL-6518 | yes | ok | — | — | — | — |
| SL-6519 |  | hit | ML-KEM | — | yes | — |
| SL-6520 |  | hit | ML-DSA | — | yes | — |
| SL-6521 |  | hit | ML-KEM | — | yes | — |
| SL-6522 |  | hit | ML-KEM | — | yes | — |
| SL-6523 |  | parent_only | EC | — | — | — |
| SL-6524 |  | hit | DH | — | yes | — |
| SL-6525 |  | parent_only | EC | — | — | — |
| SL-6526 |  | hit | RSA | — | no | — |
| SL-6527 | yes | false_alarm | EC | — | — | — |
| SL-7000 |  | miss | — | — | — | — |
| SL-7001 |  | miss | — | — | — | — |
| SL-7002 |  | miss | — | — | — | — |
| SL-7003 |  | miss | — | — | — | — |
| SL-7004 |  | miss | — | — | — | — |
| SL-7005 |  | miss | — | — | — | — |
| SL-7006 |  | miss | — | — | — | — |
| SL-7007 |  | miss | — | — | — | — |
| SL-7008 |  | miss | — | — | — | — |
| SL-7009 |  | miss | — | — | — | — |
| SL-7010 |  | miss | — | — | — | — |
| SL-7011 |  | miss | — | — | — | — |
| SL-7012 |  | miss | — | — | — | — |
| SL-7013 |  | miss | — | — | — | — |
| SL-7014 |  | miss | — | — | — | — |
| SL-7015 |  | miss | — | — | — | — |
| SL-7016 |  | miss | — | — | — | — |
| SL-7017 |  | miss | — | — | — | — |
| SL-7018 |  | miss | — | — | — | — |
| SL-7019 |  | miss | — | — | — | — |
| SL-7020 |  | miss | — | — | — | — |
| SL-7021 |  | miss | — | — | — | — |
| SL-7022 |  | hit | ML-DSA | — | yes | — |
| SL-7023 |  | hit | MD5 | — | yes | — |
| SL-7024 |  | hit | MD5 | — | yes | — |
| SL-7025 |  | hit | SHA-1 | — | yes | — |
| SL-7026 |  | hit | SHA-1 | — | yes | — |
| SL-7027 | yes | ok | — | — | — | — |
| SL-7028 | yes | ok | — | — | — | — |
| SL-7029 | yes | false_alarm | ML-DSA | — | — | — |
| SL-7030 | yes | false_alarm | EC | — | — | — |
