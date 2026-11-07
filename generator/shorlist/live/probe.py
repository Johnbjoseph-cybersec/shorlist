"""Reference client: what is actually on the wire, independent of the scanners.

Runs inside the harness image (python3, openssl s_client, ssh, tcpdump), next to the planted
server, and prints one JSON object. Standard library only; it is mounted read-only and run as

    python3 /probe/probe.py <job.json>

job: {"protocol": "tls"|"ssh", "host": "srv", "port": 443, "items": [<wire.yaml items>],
      "pcap": "/out/handshake.pcap" or null}

For TLS:
  group         `openssl s_client -groups <name>`; on the wire when s_client reports that group
                ("Negotiated TLS1.3 group: X" or "Peer Temp Key: ..., X").
  sigalg        `openssl s_client -sigalgs <name>`; on the wire when "Peer signature type: <name>".
  cipher_suite  a raw TLS 1.2 ClientHello offering only those code points (so suites that this
                OpenSSL no longer implements, RC4 and 3DES, can still be asked for); on the wire
                when the server answers with a ServerHello choosing one of them. The not_seen
                items of a row are offered together in one hello: any ServerHello is a contradiction.
For SSH:
  `ssh -vv` with every algorithm this OpenSSH knows; the server's KEXINIT name-lists are read from
  the "peer server KEXINIT proposal" block and server-sig-algs from the EXT_INFO debug line.

With "pcap", one broad handshake (the client offering everything it supports) is captured with
tcpdump, after the targeted probes, for the passive (Zeek) adapter.
"""
from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

ALL_GROUPS = ("X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:x25519:secp256r1:secp384r1:secp521r1:"
              "x448:ffdhe2048:ffdhe3072:ffdhe4096")
# OpenSSL spellings in s_client output -> IANA names
GROUP_OUT = {"x25519": "x25519", "x448": "x448", "prime256v1": "secp256r1", "secp256r1": "secp256r1",
             "secp384r1": "secp384r1", "secp521r1": "secp521r1"}


def run(argv, timeout=20, stdin=b""):
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        return (p.stdout + p.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        return ((e.stdout or b"") + (e.stderr or b"")).decode("utf-8", "replace") + "\n<timeout>"


def s_client_group(out: str) -> str | None:
    m = re.search(r"Negotiated TLS1\.3 group: (\S+)", out)
    if m:
        return GROUP_OUT.get(m.group(1).lower(), m.group(1))
    m = re.search(r"(?:Peer|Server) Temp Key: (?:ECDH, )?([A-Za-z0-9]+)", out)
    if m:
        return GROUP_OUT.get(m.group(1).lower(), m.group(1))
    return None


def s_client_sigalg(out: str) -> str | None:
    m = re.search(r"Peer signature type: (\S+)", out)
    return m.group(1) if m else None


def client_hello(codes: list[int], host: str) -> bytes:
    """A TLS 1.2 ClientHello offering exactly `codes`, with the common groups and signature schemes."""
    sni = host.encode()
    ext = b""
    ext += struct.pack("!HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni           # server_name
    groups = [0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101]
    ext += struct.pack("!HHH", 10, 2 + 2 * len(groups), 2 * len(groups)) + b"".join(struct.pack("!H", g) for g in groups)
    ext += struct.pack("!HHB", 11, 2, 1) + b"\x00"                                          # ec_point_formats
    sigs = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203, 0x0202]
    ext += struct.pack("!HHH", 13, 2 + 2 * len(sigs), 2 * len(sigs)) + b"".join(struct.pack("!H", s) for s in sigs)
    suites = b"".join(struct.pack("!H", c) for c in codes)
    body = (b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack("!H", len(suites)) + suites + b"\x01\x00"
            + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def parse_server_answer(data: bytes) -> dict:
    """First record of the server's answer: a ServerHello's cipher suite, or an alert."""
    if len(data) < 5:
        return {"answer": "closed"}
    ctype = data[0]
    if ctype == 0x15 and len(data) >= 7:
        return {"answer": "alert", "alert": data[6]}
    if ctype == 0x16 and len(data) >= 9 and data[5] == 0x02:
        sid_len = data[5 + 4 + 2 + 32]
        off = 5 + 4 + 2 + 32 + 1 + sid_len
        if len(data) >= off + 2:
            return {"answer": "server_hello", "version": f"0x{data[9]:02X}{data[10]:02X}",
                    "cipher": f"0x{struct.unpack('!H', data[off:off + 2])[0]:04X}"}
    return {"answer": "other", "first_bytes": data[:8].hex()}


def raw_hello(host: str, port: int, codes: list[int], timeout: float = 5.0) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(client_hello(codes, host))
            data = b""
            while len(data) < 200:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data[:1] == b"\x15" and len(data) >= 7:
                    break
                if data[:1] == b"\x16" and len(data) >= 60:
                    break
            return parse_server_answer(data)
    except OSError as e:
        return {"answer": "error", "error": str(e)}


def parse_ssh_vv(out: str) -> dict:
    """The server's KEXINIT name-lists and server-sig-algs from `ssh -vv` debug output."""
    lists: dict[str, list[str]] = {}
    block = out.split("peer server KEXINIT proposal", 1)
    if len(block) == 2:
        keys = {"KEX algorithms": "kex", "host key algorithms": "hostkey", "ciphers ctos": "cipher",
                "ciphers stoc": "cipher", "MACs ctos": "mac", "MACs stoc": "mac"}
        for line in block[1].splitlines()[:12]:
            m = re.match(r"debug2: ([A-Za-z ]+?): (.*)$", line.strip())
            if m and m.group(1) in keys:
                lists.setdefault(keys[m.group(1)], [])
                for n in m.group(2).split(","):
                    if n and n not in lists[keys[m.group(1)]]:
                        lists[keys[m.group(1)]].append(n)
    m = re.search(r"server-sig-algs=<([^>]*)>", out)
    if m:
        lists["server_sig_alg"] = [n for n in m.group(1).split(",") if n]
    return lists


def ssh_all_opts() -> list[str]:
    q = lambda what: ",".join(run(["ssh", "-Q", what]).split())  # noqa: E731
    return ["-o", "KexAlgorithms=" + q("kex"), "-o", "HostKeyAlgorithms=" + q("HostKeyAlgorithms"),
            "-o", "Ciphers=" + q("cipher"), "-o", "MACs=" + q("mac")]


def ssh_vv(host: str, port: int) -> str:
    return run(["ssh", "-vv", "-p", str(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8", *ssh_all_opts(),
                f"probe@{host}", "true"], timeout=25)


def tls_probe(job: dict) -> list[dict]:
    host, port = job["host"], job["port"]
    target = f"{host}:{port}"
    out = []
    not_seen_suites = [i for i in job["items"] if i["kind"] == "cipher_suite" and i["expect"] == "not_seen"]
    for it in job["items"]:
        r = {"name": it["name"], "kind": it["kind"], "expect": it["expect"]}
        if it["kind"] == "group":
            o = run(["openssl", "s_client", "-connect", target, "-groups", it["name"]])
            got = s_client_group(o)
            r.update(on_wire=(got or "").lower() == it["name"].lower(), evidence=f"s_client -groups {it['name']}: negotiated {got}")
        elif it["kind"] == "sigalg":
            o = run(["openssl", "s_client", "-connect", target, "-sigalgs", it["name"]])
            got = s_client_sigalg(o)
            if got != it["name"]:  # a TLS 1.2-only scheme (rsa_pkcs1_*) is refused in TLS 1.3
                o = run(["openssl", "s_client", "-connect", target, "-tls1_2", "-cipher", "ECDHE:DHE:@SECLEVEL=0",
                         "-sigalgs", it["name"]])
                got = s_client_sigalg(o)
            r.update(on_wire=got == it["name"], evidence=f"s_client -sigalgs {it['name']}: peer signature type {got}")
        elif it["kind"] == "cipher_suite" and it["expect"] == "seen":
            a = raw_hello(host, port, [int(it["code"], 16)])
            r.update(on_wire=(a.get("cipher") or "").lower() == it["code"].lower(), evidence=f"raw ClientHello {it['code']}: {a}")
        else:
            continue
        out.append(r)
    if not_seen_suites:
        a = raw_hello(host, port, [int(i["code"], 16) for i in not_seen_suites])
        chosen = a.get("cipher")
        out.append({"name": f"{len(not_seen_suites)} not_seen suites", "kind": "cipher_suite_set", "expect": "not_seen",
                    "on_wire": a.get("answer") == "server_hello", "on_wire_items": [chosen] if chosen else [],
                    "evidence": f"raw ClientHello offering the {len(not_seen_suites)} not_seen suites together: {a}"})
    return out


def ssh_probe(job: dict, vv: str) -> list[dict]:
    lists = parse_ssh_vv(vv)
    out = []
    for it in job["items"]:
        have = lists.get(it["kind"])
        r = {"name": it["name"], "kind": it["kind"], "expect": it["expect"]}
        if have is None:
            r.update(on_wire=None, evidence=f"no {it['kind']} list in the ssh -vv output")
        else:
            r.update(on_wire=it["name"] in have, evidence=f"server {it['kind']} list: {','.join(have)}")
        out.append(r)
    return out


def broad_tls(target: str) -> str:
    return run(["openssl", "s_client", "-connect", target, "-groups", ALL_GROUPS,
                "-cipher", "ALL:COMPLEMENTOFALL:@SECLEVEL=0"])


def main(job_path: str) -> int:
    job = json.load(open(job_path))
    host, port = job["host"], job["port"]
    res: dict = {"protocol": job["protocol"]}
    if job["protocol"] == "tls":
        res["items"] = tls_probe(job)
    else:
        vv = ssh_vv(host, port)
        res["server_lists"] = parse_ssh_vv(vv)
        res["items"] = ssh_probe(job, vv)
    if job.get("pcap"):
        td = subprocess.Popen(["tcpdump", "-i", "eth0", "-U", "-s", "0", "-w", job["pcap"], "tcp", "port", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        broad = broad_tls(f"{host}:{port}") if job["protocol"] == "tls" else ssh_vv(host, port)
        time.sleep(1.0)
        td.terminate()
        td.wait(timeout=5)
        res["pcap_handshake"] = (s_client_group(broad), re.findall(r"Cipher is (\S+)", broad)[:1]) if job["protocol"] == "tls" \
            else re.findall(r"debug1: kex: algorithm: (\S+)", broad)[:1]
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
