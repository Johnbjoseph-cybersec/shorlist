"""How a listener in listeners.yaml is planted as a live server.

Copied from the network axis (shorlist-mreja generator/shorlist/live/servers.py: HARNESS_IMAGE,
IMAGES, VERSIONS, APACHE_PREAMBLE and the nginx / apache / s_server branches of plant()), with one
change: the configuration comes from a listener of listeners.yaml instead of a catalogue row.
The OpenSSH branch is not copied: SSH rows are not scored on this axis (no_spec_structure).

    nginx     `config` is the whole /etc/nginx/nginx.conf, run with -g 'daemon off;'
    apache    `config` is a fragment (Listen + VirtualHost); a fixed preamble with no SSL directive
              loads mod_ssl and Includes it
    s_server  `args` are appended to `openssl s_server -accept 443 -cert .. -key .. -www`
`cert.pem` / `key.pem` are an RSA-2048 or ECDSA P-256 certificate made at harness image build.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

HARNESS_IMAGE = "shorlist-live:1"  # containers/live/Dockerfile (copied unchanged from the network axis)
IMAGES = {
    "nginx": "nginx@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311",   # nginx:1.30.6-alpine
    "apache": "httpd@sha256:d72968666c0a6961b07036d85fc053bc3cf640583cb1ff8360e1617818f164dc",  # httpd:2.4.69-alpine
    "s_server": HARNESS_IMAGE,
}
VERSIONS = {  # read inside the images on 2026-11-07 by the network axis
    "nginx": "nginx/1.30.6, built with OpenSSL 3.5.8, running with OpenSSL 3.5.9 (Alpine 3.24)",
    "apache": "Apache/2.4.69 (Unix), libssl3-3.5.9-r0 (Alpine 3.24)",
    "s_server": "OpenSSL 3.5.9 s_server (Alpine 3.24.3, openssl-3.5.9-r0)",
}

APACHE_PREAMBLE = """ServerRoot "/usr/local/apache2"
ServerName srv
PidFile /tmp/httpd.pid
ErrorLog /proc/self/fd/2
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
LoadModule ssl_module modules/mod_ssl.so
User daemon
Group daemon
Include /row/httpd.conf
"""


@dataclass
class Plant:
    image: str
    port: int
    mounts: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    entrypoint: str | None = None
    check: list[str] | None = None
    ready: str = ""
    files: dict[str, str] = field(default_factory=dict)


def config_sha256(listener: dict) -> str:
    """What a capture is bound to: server, certificate and configuration text (or s_server args)."""
    body = {"server": listener["server"], "cert": listener.get("cert", "rsa"),
            "config": listener.get("config"), "args": listener.get("args")}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _port(template: str, pattern: str, default: int) -> int:
    m = re.search(pattern, template, re.M)
    return int(m.group(1)) if m else default


def plant(listener: dict, rowdir: Path, certdir: Path) -> Plant:
    server = listener["server"]
    cert = listener.get("cert", "rsa")
    crt, key = f"{certdir}/{cert}.pem", f"{certdir}/{cert}.key"
    if server == "nginx":
        tpl = listener["config"]
        p = Plant(IMAGES[server], _port(tpl, r"^\s*listen\s+(\d+)", 443),
                  mounts=["-v", f"{rowdir}/nginx.conf:/etc/nginx/nginx.conf:ro",
                          "-v", f"{crt}:/etc/nginx/cert.pem:ro", "-v", f"{key}:/etc/nginx/key.pem:ro"],
                  entrypoint="nginx", command=["-g", "daemon off;"], check=["-t"], files={"nginx.conf": tpl})
    elif server == "apache":
        tpl = listener["config"]
        p = Plant(IMAGES[server], _port(tpl, r"^\s*Listen\s+(\d+)", 443),
                  mounts=["-v", f"{rowdir}/shorlist.conf:/usr/local/apache2/conf/shorlist.conf:ro",
                          "-v", f"{crt}:/usr/local/apache2/cert.pem:ro", "-v", f"{key}:/usr/local/apache2/key.pem:ro"],
                  command=["httpd", "-DFOREGROUND", "-f", "/usr/local/apache2/conf/shorlist.conf"],
                  check=["httpd", "-t", "-f", "/usr/local/apache2/conf/shorlist.conf"], ready="resuming normal operations",
                  files={"shorlist.conf": APACHE_PREAMBLE, "httpd.conf": tpl})
    elif server == "s_server":
        p = Plant(IMAGES[server], 443,
                  command=["openssl", "s_server", "-accept", "443", "-cert", f"/certs/{cert}.pem",
                           "-key", f"/certs/{cert}.key", "-www", *listener["args"]],
                  ready="ACCEPT", files={"s_server.args": " ".join(listener["args"]) + "\n"})
    else:
        raise ValueError(f"no harness for server {server!r}")
    p.mounts = ["-v", f"{rowdir}:/row:ro", *p.mounts]
    for name, content in p.files.items():
        (rowdir / name).write_text(content)
    return p
