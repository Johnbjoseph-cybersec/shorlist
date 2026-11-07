"""How each server is planted from a row.

`planting` in wire.yaml says which mode a row uses:
    verbatim            the row's context_template is the server's whole configuration file
                        (nginx: /etc/nginx/nginx.conf, run with -g 'daemon off;')
    verbatim+hostkeys   OpenSSH: three HostKey lines (RSA, ECDSA P-256, Ed25519 keys made at image build)
                        and `PerSourcePenalties no` are put before the template. Without the last line
                        OpenSSH 10 penalises the source address after the reference client's and a scanner's
                        unauthenticated connections, and the next scanner (docker reuses the address) gets
                        no KEXINIT. Neither line names an algorithm.
    preamble+include    Apache httpd: the template is a fragment (Listen + VirtualHost), so a fixed preamble
                        (ServerRoot, ServerName, LoadModule mpm_event/authz_core/unixd/socache_shmcb/ssl,
                        User/Group) loads mod_ssl and Includes it. The preamble has no SSL directive.
    mapped              OpenSSL C API rows: the string passed to SSL_CTX_set1_groups_list /
                        SSL_CTX_set1_sigalgs_list is given to `openssl s_server -groups/-sigalgs`.
The template's `cert.pem` / `key.pem` are an RSA-2048 or ECDSA P-256 certificate (`cert` in wire.yaml).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

HARNESS_IMAGE = "shorlist-live:1"  # containers/live/Dockerfile; its image ID is recorded in every result
IMAGES = {
    "nginx": "nginx@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311",   # nginx:1.30.6-alpine
    "apache": "httpd@sha256:d72968666c0a6961b07036d85fc053bc3cf640583cb1ff8360e1617818f164dc",  # httpd:2.4.69-alpine
    "openssh": HARNESS_IMAGE,
    "s_server": HARNESS_IMAGE,
}
VERSIONS = {  # read inside the images on 2026-11-07
    "nginx": "nginx/1.30.6, built with OpenSSL 3.5.8, running with OpenSSL 3.5.9 (Alpine 3.24)",
    "apache": "Apache/2.4.69 (Unix), libssl3-3.5.9-r0 (Alpine 3.24)",
    "openssh": "OpenSSH_10.3p1, OpenSSL 3.5.9 (Alpine 3.24.3, openssh-server-10.3_p1-r2)",
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
SSHD_PREAMBLE = ("HostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\n"
                 "HostKey /etc/ssh/ssh_host_ed25519_key\nPerSourcePenalties no\n")


@dataclass
class Plant:
    image: str
    port: int
    mounts: list[str] = field(default_factory=list)     # -v arguments
    command: list[str] = field(default_factory=list)    # server start (after --entrypoint, if set)
    entrypoint: str | None = None                        # bypasses an image's entrypoint script
    check: list[str] | None = None                       # config test (exit != 0: rejected), or None
    ready: str = ""                                      # log text that says the server listens
    files: dict[str, str] = field(default_factory=dict)  # name in the row dir -> content


def _port(template: str, pattern: str, default: int) -> int:
    m = re.search(pattern, template, re.M)
    return int(m.group(1)) if m else default


def plant(row: dict, wire: dict, rowdir: Path, certdir: Path) -> Plant:
    """Write the row's files into rowdir and say how to start the server."""
    server, tpl = wire["server"], row["context_template"]
    cert = wire.get("cert", "rsa")
    crt, key = f"{certdir}/{cert}.pem", f"{certdir}/{cert}.key"
    if server == "openssh":
        p = Plant(IMAGES[server], _port(tpl, r"^\s*Port\s+(\d+)", 22),
                  command=["/usr/sbin/sshd", "-D", "-e", "-f", "/row/sshd_config"],
                  check=["/usr/sbin/sshd", "-t", "-f", "/row/sshd_config"], ready="Server listening",
                  files={"sshd_config": SSHD_PREAMBLE + tpl})
    elif server == "nginx":
        p = Plant(IMAGES[server], _port(tpl, r"^\s*listen\s+(\d+)", 443),
                  mounts=["-v", f"{rowdir}/nginx.conf:/etc/nginx/nginx.conf:ro",
                          "-v", f"{crt}:/etc/nginx/cert.pem:ro", "-v", f"{key}:/etc/nginx/key.pem:ro"],
                  entrypoint="nginx", command=["-g", "daemon off;"], check=["-t"], ready="",
                  files={"nginx.conf": tpl})
    elif server == "apache":
        p = Plant(IMAGES[server], _port(tpl, r"^\s*Listen\s+(\d+)", 443),
                  mounts=["-v", f"{rowdir}/shorlist.conf:/usr/local/apache2/conf/shorlist.conf:ro",
                          "-v", f"{crt}:/usr/local/apache2/cert.pem:ro", "-v", f"{key}:/usr/local/apache2/key.pem:ro"],
                  command=["httpd", "-DFOREGROUND", "-f", "/usr/local/apache2/conf/shorlist.conf"],
                  check=["httpd", "-t", "-f", "/usr/local/apache2/conf/shorlist.conf"], ready="resuming normal operations",
                  files={"shorlist.conf": APACHE_PREAMBLE, "httpd.conf": tpl})
    elif server == "s_server":
        p = Plant(IMAGES[server], 443,
                  command=["openssl", "s_server", "-accept", "443", "-cert", f"/certs/{cert}.pem",
                           "-key", f"/certs/{cert}.key", "-www", *wire["s_server_args"]],
                  check=None, ready="ACCEPT", files={"s_server.args": " ".join(wire["s_server_args"]) + "\n"})
    else:
        raise ValueError(f"no harness for server {server!r}")
    p.mounts = ["-v", f"{rowdir}:/row:ro", *p.mounts]
    for name, content in p.files.items():
        (rowdir / name).write_text(content)
    return p
