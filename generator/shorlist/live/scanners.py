"""Network scanner adapters.

Each adapter knows one scanner's invocation and output; it turns the output into observations
`(kind, value)` with these kinds:

    tls  group, cipher_suite, sigalg
    ssh  kex, hostkey, cipher, mac, server_sig_alg

`value` is the IANA name where the adapter can tell it (groups are normalised to the IANA spelling,
cipher suites carry the IANA name and, where the scanner gives it, the hex code point "0x009C").
The scorer never sees a scanner's own field names.

Every scanner runs in a container pinned by digest, on the run's `--internal` docker network,
pointed only at the planted server (`srv`).
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

# scanner / OpenSSL spellings -> IANA TLS Supported Groups names
GROUP_NAMES = {
    "prime256v1": "secp256r1", "p-256": "secp256r1", "secp256r1": "secp256r1", "ecdh_secp256r1": "secp256r1",
    "p-384": "secp384r1", "secp384r1": "secp384r1", "ecdh_secp384r1": "secp384r1",
    "p-521": "secp521r1", "secp521r1": "secp521r1", "ecdh_secp521r1": "secp521r1",
    "x25519": "x25519", "ecdh_x25519": "x25519", "x448": "x448", "ecdh_x448": "x448",
    "x25519mlkem768": "X25519MLKEM768", "secp256r1mlkem768": "SecP256r1MLKEM768",
    "secp384r1mlkem1024": "SecP384r1MLKEM1024", "mlkem512": "MLKEM512", "mlkem768": "MLKEM768", "mlkem1024": "MLKEM1024",
    "ffdhe2048": "ffdhe2048", "ffdhe3072": "ffdhe3072", "ffdhe4096": "ffdhe4096", "ffdhe6144": "ffdhe6144",
    "ffdhe8192": "ffdhe8192", "brainpoolp256r1": "brainpoolP256r1", "brainpoolp384r1": "brainpoolP384r1",
    "brainpoolp512r1": "brainpoolP512r1",
}
# OpenSSL "SIG+HASH" spellings (testssl.sh prints these) -> IANA SignatureScheme names
SIGALG_NAMES = {
    "RSA+SHA256": "rsa_pkcs1_sha256", "RSA+SHA384": "rsa_pkcs1_sha384", "RSA+SHA512": "rsa_pkcs1_sha512",
    "RSA+SHA1": "rsa_pkcs1_sha1", "ECDSA+SHA256": "ecdsa_secp256r1_sha256", "ECDSA+SHA384": "ecdsa_secp384r1_sha384",
    "ECDSA+SHA512": "ecdsa_secp521r1_sha512", "ECDSA+SHA1": "ecdsa_sha1",
    "RSA-PSS-RSAE+SHA256": "rsa_pss_rsae_sha256", "RSA-PSS-RSAE+SHA384": "rsa_pss_rsae_sha384",
    "RSA-PSS-RSAE+SHA512": "rsa_pss_rsae_sha512", "RSA-PSS-PSS+SHA256": "rsa_pss_pss_sha256",
    "RSA-PSS-PSS+SHA384": "rsa_pss_pss_sha384", "RSA-PSS-PSS+SHA512": "rsa_pss_pss_sha512",
    "ED25519": "ed25519", "ED448": "ed448",
}


def group(name: str) -> str:
    return GROUP_NAMES.get(name.strip().lower(), name.strip())


def hexcode(h: str) -> str:
    """testssl.sh 'x9c' / 'xc02f' / '0x00,0x9C' -> '0x009C'."""
    h = h.strip().lower().replace("0x", "").replace(",", "").lstrip("x")
    return f"0x{int(h, 16):04X}"


Obs = tuple  # (kind, value)


@dataclass
class ScannerAdapter:
    name: str
    image: str           # pinned by digest
    tag: str             # the tag the digest was pulled as (for humans)
    protocols: tuple
    controls: dict       # protocol -> (row that must be caught, decoy that must not be reported)
    passive: bool = False

    def argv(self, protocol: str, host: str, port: int) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def parse(self, protocol: str, stdout: str, outdir: Path) -> set:  # pragma: no cover - interface
        raise NotImplementedError

    version_argv: list = None
    version_re: str = ""

    def version(self, text: str) -> str:
        m = re.search(self.version_re, re.sub(r"\x1b\[[0-9;]*m", "", text))
        return f"{self.name} {m.group(1)}" if m else f"{self.name} ({self.tag}, version string not found)"


class SshAudit(ScannerAdapter):
    """ssh-audit -j: JSON with kex[], key[], enc[], mac[] lists of {"algorithm": ...}. It reads the
    server's KEXINIT; it does not report the server-sig-algs extension (checked on its JSON: no such key)."""

    def argv(self, protocol, host, port):
        return ["-j", "-p", str(port), host]

    def parse(self, protocol, stdout, outdir):
        d = json.loads(stdout)
        out = set()
        for key, kind in (("kex", "kex"), ("key", "hostkey"), ("enc", "cipher"), ("mac", "mac")):
            for a in d.get(key, []):
                out.add((kind, a["algorithm"]))
        return out


class TestSSL(ScannerAdapter):
    """testssl.sh -E (each cipher per protocol) -f (forward secrecy: KEMs, ECDHE curves, DH groups,
    signature algorithms), JSON file. Cipher suites from ids `cipher-<proto>_x<hex>` (the hex code point and
    the IANA name are in `finding`); groups from FS_KEMs / FS_ECDHE_curves / DH_groups; signature schemes
    from FS_TLS12_sig_algs / FS_TLS13_sig_algs (OpenSSL SIG+HASH spellings)."""

    def argv(self, protocol, host, port):
        return ["--jsonfile", "/out/testssl.json", "--warnings", "off", "--quiet", "--color", "0", "-E", "-f",
                f"{host}:{port}"]

    def parse(self, protocol, stdout, outdir):
        return self.parse_json(json.loads((outdir / "testssl.json").read_text()))

    @staticmethod
    def parse_json(d: list) -> set:
        out = set()
        for x in d:
            i, f = x["id"], x.get("finding", "")
            m = re.match(r"cipher-(?:tls1|tls1_1|tls1_2|tls1_3|ssl3|ssl2)_x([0-9a-f]+)$", i)
            if m:
                out.add(("cipher_suite", hexcode(m.group(1))))
                std = re.search(r"\b((?:TLS|SSL)_\w+)\s*$", f)
                if std:
                    out.add(("cipher_suite", std.group(1)))
            elif i in ("FS_KEMs", "FS_ECDHE_curves", "DH_groups", "FS_DH_groups"):
                if f.startswith("No ") or " not " in f:  # "No KEMs offered"
                    continue
                for g in f.split():
                    out.add(("group", group(g)))
            elif i in ("FS_TLS12_sig_algs", "FS_TLS13_sig_algs"):
                if f.startswith("No ") or " not " in f:
                    continue
                for s in f.split():
                    out.add(("sigalg", SIGALG_NAMES.get(s, s)))
        return out


class SSLyze(ScannerAdapter):
    """sslyze --json_out=-: accepted cipher suites per TLS version (IANA `name`, `openssl_name`), the
    ephemeral key's curve per accepted suite, and elliptic_curves.supported_curves. It does not report
    signature schemes."""

    def argv(self, protocol, host, port):
        return ["--json_out=-", f"{host}:{port}"]

    def parse(self, protocol, stdout, outdir):
        return self.parse_json(json.loads(stdout))

    @staticmethod
    def parse_json(d: dict) -> set:
        out = set()
        for srv in d.get("server_scan_results", []):
            res = srv.get("scan_result") or {}
            for k, v in res.items():
                if not k.endswith("_cipher_suites") or not v or v.get("status") != "COMPLETED":
                    continue
                for a in v["result"].get("accepted_cipher_suites", []):
                    out.add(("cipher_suite", a["cipher_suite"]["name"]))
                    ek = a.get("ephemeral_key") or {}
                    if ek.get("curve_name"):
                        out.add(("group", group(ek["curve_name"])))
            ec = res.get("elliptic_curves") or {}
            for c in ((ec.get("result") or {}).get("supported_curves") or []):
                out.add(("group", group(c["name"])))
        return out


class Nmap(ScannerAdapter):
    """nmap -sT -Pn with ssl-enum-ciphers (TLS) or ssh2-enum-algos (SSH), XML on stdout. ssl-enum-ciphers
    lists accepted suites per protocol with `kex_info`: for ECDHE/TLS 1.3 the group name (e.g.
    `X25519MLKEM768`, `secp256r1`), for RSA/DHE a key size ("rsa 2048", "dh 2048"), which is not a group.
    Its TLS 1.3 suite names (TLS_AKE_WITH_*) are not IANA names and are not used."""

    def argv(self, protocol, host, port):
        script = "ssl-enum-ciphers" if protocol == "tls" else "ssh2-enum-algos"
        return ["-Pn", "-sT", "-p", str(port), "--script", script, "-oX", "-", host]

    def parse(self, protocol, stdout, outdir):
        return self.parse_xml(stdout)

    @staticmethod
    def parse_xml(text: str) -> set:
        out = set()
        root = ET.fromstring(text)
        for sc in root.iter("script"):
            if sc.get("id") == "ssl-enum-ciphers":
                for proto in sc.findall("table"):
                    for ciphers in proto.findall("table[@key='ciphers']"):
                        for c in ciphers.findall("table"):
                            el = {e.get("key"): (e.text or "") for e in c.findall("elem")}
                            if el.get("name") and not el["name"].startswith("TLS_AKE_"):
                                out.add(("cipher_suite", el["name"]))
                            ki = el.get("kex_info", "")
                            if ki and not re.match(r"(rsa|dh) \d+$", ki):
                                out.add(("group", group(ki)))
            elif sc.get("id") == "ssh2-enum-algos":
                keys = {"kex_algorithms": "kex", "server_host_key_algorithms": "hostkey",
                        "encryption_algorithms": "cipher", "mac_algorithms": "mac"}
                for t in sc.findall("table"):
                    kind = keys.get(t.get("key"))
                    if kind:
                        for e in t.findall("elem"):
                            out.add((kind, e.text))
        return out


class Zeek(ScannerAdapter):
    """Zeek, passive: `zeek -C -r handshake.pcap` with JSON logs, on the pcap of one broad handshake made by the
    reference client (OpenSSL 3.5.9 s_client offering every group and suite it has; OpenSSH 10.3 ssh offering
    every algorithm it has). Default scripts only. ssl.log carries the *negotiated* cipher and curve, ssh.log the
    negotiated kex/host key/cipher/MAC: one choice per connection, not the server's offer set."""

    def argv(self, protocol, host, port):
        return ["sh", "-c", "cd /out && zeek -C -r /out/handshake.pcap LogAscii::use_json=T"]

    def parse(self, protocol, stdout, outdir):
        return self.parse_logs((outdir / "ssl.log").read_text() if (outdir / "ssl.log").exists() else "",
                               (outdir / "ssh.log").read_text() if (outdir / "ssh.log").exists() else "")

    @staticmethod
    def parse_logs(ssl_log: str, ssh_log: str) -> set:
        out = set()
        for line in ssl_log.splitlines():
            if line.startswith("{"):
                r = json.loads(line)
                if r.get("cipher"):
                    out.add(("cipher_suite", r["cipher"]))
                if r.get("curve"):
                    out.add(("group", group(r["curve"])))
        for line in ssh_log.splitlines():
            if line.startswith("{"):
                r = json.loads(line)
                for f, kind in (("kex_alg", "kex"), ("host_key_alg", "hostkey"), ("cipher_alg", "cipher"),
                                ("mac_alg", "mac")):
                    if r.get(f):
                        out.add((kind, r[f]))
        return out


SCANNERS: dict[str, ScannerAdapter] = {a.name: a for a in (
    SshAudit("ssh-audit", "positronsecurity/ssh-audit@sha256:6d5dee75fe91b5f6279f683f0e7d4374d2ba83e2227c8d9a17097aac2775127d",
             "positronsecurity/ssh-audit:v3.9.0", ("ssh",), {"ssh": ("SL-0015", "SL-0029")},
             version_argv=["--help"], version_re=r"ssh-audit\.py (v[\d.]+)"),
    TestSSL("testssl.sh", "drwetter/testssl.sh@sha256:64bab3c1fd8eee440f68d5e020dd633c1f2d375fe0ae593bdfec2725110a7e29",
            "drwetter/testssl.sh:3.2", ("tls",), {"tls": ("SL-0011", "SL-0022")},
            version_argv=["--version"], version_re=r"testssl\.sh\S*\s+version\s+([\d.]+\S*)"),
    SSLyze("sslyze", "nablac0d3/sslyze@sha256:3060ce2f3168cf1d74e5a0989660008052bee645826875122ba7edea95e5b95c",
           "nablac0d3/sslyze:6.3.1", ("tls",), {"tls": ("SL-6503", "SL-0022")},
           version_argv=["--help"], version_re=r"SSLyze version ([\d.]+)"),
    Nmap("nmap", "instrumentisto/nmap@sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827",
         "instrumentisto/nmap:7.98", ("tls", "ssh"), {"tls": ("SL-0011", "SL-0022"), "ssh": ("SL-0015", "SL-0029")},
         version_argv=["--version"], version_re=r"Nmap version ([\d.]+)"),
    Zeek("zeek", "zeek/zeek@sha256:3882d4b46fa82993ecb50b8881389fe4e40e8e2ba77547402f72b65a5a89591b",
         "zeek/zeek:8.0.11", ("tls", "ssh"), {"tls": ("SL-0012", "SL-0022"), "ssh": ("SL-1174", "SL-0029")},
         passive=True, version_argv=["zeek", "--version"], version_re=r"zeek version ([\d.]+)"),
)}
