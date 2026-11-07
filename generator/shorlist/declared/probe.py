"""Reference client for the declaration axis: the ACCEPTED SET of one TLS listener.

Runs inside the network axis's harness image (shorlist-live:1: python3 + openssl s_client), next to
the planted server, standard library only, and prints one JSON object:

    python3 /probe/probe.py <job.json>

job: {"host": "srv", "port": 443,
      "groups": ["X25519MLKEM768", ...],                 IANA names, each offered ALONE
      "suites13": [["0x1301", "TLS_AES_128_GCM_SHA256"], ...],
      "suites12": [["0xC02F", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"], ...]}

One handshake per candidate (scope rule S2), never one negotiated handshake:
  group, TLS 1.3   `openssl s_client -tls1_3 -groups <name>`; accepted when s_client reports
                   "Negotiated TLS1.3 group: <name>".
  group, TLS 1.2   only for the elliptic-curve groups (TLS 1.2 negotiates no FFDHE or ML-KEM group in
                   OpenSSL): `openssl s_client -tls1_2 -cipher ECDHE:@SECLEVEL=0 -groups <name>`;
                   accepted when "Peer Temp Key" / "Server Temp Key" names that curve. Limitation: with
                   an ECDSA certificate in TLS 1.2 the offered group must also be the certificate's
                   curve (RFC 8422), so a group offered alone is refused for that reason; listeners
                   that serve TLS 1.2 groups use an RSA certificate, except L-SSV-4 (P-256 cert, P-256 group).
  suite, TLS 1.3   `openssl s_client -tls1_3 -ciphersuites <name> -groups <every candidate group>`
                   (so a listener with only pure ML-KEM groups can still complete); accepted when the
                   handshake reports "Cipher is <name>" with protocol TLSv1.3.
  suite, TLS 1.2   a raw TLS 1.2 ClientHello offering that one code point (so suites this OpenSSL
                   client would not send can still be asked for); accepted when the server answers
                   with a ServerHello choosing it.

The raw ClientHello and the s_client output parsing are copied from the network axis
(shorlist-mreja generator/shorlist/live/probe.py: client_hello, parse_server_answer, raw_hello, run,
the Temp Key regular expression); the per-candidate enumeration is new here.
"""
from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import sys

EC_TLS12 = {"x25519", "x448", "secp256r1", "secp384r1", "secp521r1"}
# OpenSSL spellings in s_client output -> IANA names (copied from live/probe.py GROUP_OUT)
GROUP_OUT = {"x25519": "x25519", "x448": "x448", "prime256v1": "secp256r1", "secp256r1": "secp256r1",
             "secp384r1": "secp384r1", "secp521r1": "secp521r1"}


def run(argv, timeout=20, stdin=b""):
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        return (p.stdout + p.stderr).decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        return ((e.stdout or b"") + (e.stderr or b"")).decode("utf-8", "replace") + "\n<timeout>"


def negotiated_group(out: str) -> str | None:
    m = re.search(r"Negotiated TLS1\.3 group: (\S+)", out)
    if m and m.group(1) != "<NULL>":
        return GROUP_OUT.get(m.group(1).lower(), m.group(1))
    # An FFDHE group in TLS 1.3: s_client prints "<NULL>" above and "Peer Temp Key: DH, 2048 bits";
    # the client offered only one group, so the bit length names it.
    m = re.search(r"(?:Peer|Server) Temp Key: DH, (\d+) bits", out)
    if m:
        return f"ffdhe{m.group(1)}"
    m = re.search(r"(?:Peer|Server) Temp Key: (?:ECDH, )?([A-Za-z0-9]+)", out)
    if m:
        return GROUP_OUT.get(m.group(1).lower(), m.group(1))
    return None


def negotiated_cipher(out: str) -> tuple[str | None, str | None]:
    """(protocol, cipher) from s_client's "New, TLSv1.3, Cipher is X" line."""
    m = re.search(r"New, (TLSv1\.[0-3]|SSLv3), Cipher is (\S+)", out)
    return (m.group(1), m.group(2)) if m else (None, None)


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


def s_client(target: str, *args: str) -> str:
    return run(["openssl", "s_client", "-connect", target, "-servername", "srv", *args], stdin=b"Q\n")


def probe(job: dict) -> dict:
    host, port = job["host"], job["port"]
    target = f"{host}:{port}"
    groups, suites = [], []
    for g in job["groups"]:
        r = {"name": g, "tls1_3": False, "tls1_2": None, "evidence": []}
        got = negotiated_group(s_client(target, "-tls1_3", "-groups", g))
        r["tls1_3"] = (got or "").lower() == g.lower()
        r["evidence"].append(f"s_client -tls1_3 -groups {g}: negotiated {got}")
        if g in EC_TLS12:
            got = negotiated_group(s_client(target, "-tls1_2", "-cipher", "ECDHE:@SECLEVEL=0", "-groups", g))
            r["tls1_2"] = (got or "").lower() == g.lower()
            r["evidence"].append(f"s_client -tls1_2 -cipher ECDHE:@SECLEVEL=0 -groups {g}: temp key {got}")
        groups.append(r)
    for code, name in job["suites13"]:
        proto, got = negotiated_cipher(s_client(target, "-tls1_3", "-ciphersuites", name, "-groups", ":".join(job["groups"])))
        suites.append({"code": code, "name": name, "version": "1.3", "accepted": proto == "TLSv1.3" and got == name,
                       "evidence": f"s_client -tls1_3 -ciphersuites {name}: {proto} {got}"})
    for code, name in job["suites12"]:
        a = raw_hello(host, port, [int(code, 16)])
        suites.append({"code": code, "name": name, "version": "1.2",
                       "accepted": a.get("answer") == "server_hello" and (a.get("cipher") or "").upper() == code.upper()
                       and a.get("version") == "0x0303",
                       "evidence": f"raw TLS 1.2 ClientHello offering {code} alone: {a}"})
    return {"groups": groups, "suites": suites,
            "openssl": run(["openssl", "version"]).strip()}


def main(job_path: str) -> int:
    print(json.dumps(probe(json.load(open(job_path)))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
