"""Capture the accepted set of each listener in listeners.yaml (the only part of this axis that needs docker).

Per listener, at most two containers run at once, each with --cpus 1 (the network axis's pattern,
shorlist-mreja live/harness.py, copied and cut down):
    1. config test in the server image, --network none (nginx -t, httpd -t)
    2. the server, detached, on a `docker network create --internal` network, alias `srv`
    3. the reference client (declared/probe.py in the harness image), same network
Every container is started with --name and removed with `docker rm -f` in a finally block, as is the
network; the internal network has no route out.

The result is observations/<listener>.json: the per-candidate evidence, the accepted set by category
and TLS version, the candidate lists, and the sha256 of the listener configuration it was taken from
(validate refuses a row whose listener changed after its capture).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from . import registry, servers

PROBE = Path(__file__).resolve().parent / "probe.py"
OBS_FORMAT = "shorlist-declared-observation/0.1"


def docker(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(e.cmd, 124, e.stdout or "", (e.stderr or "") + f"\n<timeout after {timeout}s>")


def server_error(text: str) -> str:
    keep = [ln.strip() for ln in text.splitlines()
            if re.search(r"emerg|error|bad |unsupported|failed|fatal|invalid", ln, re.I) and not ln.startswith("/docker-entrypoint")]
    return " / ".join(keep) or text.strip()[-500:]


def job() -> dict:
    s13, s12 = registry.candidate_suites()
    return {"host": "srv", "groups": list(registry.CANDIDATE_GROUPS), "suites13": s13, "suites12": s12}


def observation(listener_id: str, listener: dict, probe_out: dict, j: dict) -> dict:
    """The probe's raw answer -> the accepted set by category, IANA code points, per TLS version."""
    groups = registry.iana("group")
    acc_g, acc_s = [], []
    for g in probe_out["groups"]:
        versions = [v for v, k in (("1.3", "tls1_3"), ("1.2", "tls1_2")) if g.get(k)]
        if versions:
            code = registry.group_code(g["name"])
            acc_g.append({"code": code, "name": groups[code]["name"], "versions": versions})
    for s in probe_out["suites"]:
        if s["accepted"]:
            acc_s.append({"code": s["code"], "name": registry.iana("cipher_suite")[s["code"]]["name"], "versions": [s["version"]]})
    return {
        "format": OBS_FORMAT,
        "listener": listener_id,
        "observation_status": "captured",
        "protocol": "tls",
        "method": "accepted",
        "server": listener["server"], "server_image": servers.IMAGES[listener["server"]],
        "server_version": servers.VERSIONS[listener["server"]],
        "config_sha256": servers.config_sha256(listener),
        "reference_client": f"{probe_out.get('openssl', 'openssl')} s_client (groups, TLS 1.3 suites) and a raw TLS 1.2 "
                            "ClientHello (TLS 1.2 suites), one handshake per candidate; declared/probe.py",
        "candidates": {"group": [registry.group_code(g) for g in j["groups"]],
                       "cipher_suite": [c for c, _ in j["suites13"]] + [c for c, _ in j["suites12"]]},
        "accepted": {"group": acc_g, "cipher_suite": acc_s},
        "evidence": probe_out,
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness_image_id": docker(["image", "inspect", servers.HARNESS_IMAGE, "--format", "{{.Id}}"]).stdout.strip(),
    }


class Capture:
    def __init__(self, log=print):
        self.log = log
        self.tag = f"shorlist-decl-{os.getpid()}"
        self.net = self.tag
        self.base = Path(tempfile.mkdtemp(prefix="shorlist-decl-"))
        self.names: set[str] = set()

    def _rm(self, name: str):
        docker(["rm", "-f", name], timeout=30)
        self.names.discard(name)

    def _run(self, name: str, args: list[str], timeout: int) -> subprocess.CompletedProcess:
        self.names.add(name)
        try:
            return docker(["run", "--rm", "--name", name, *args], timeout=timeout)
        finally:
            self._rm(name)

    def _start(self, lid: str, p: servers.Plant) -> tuple[bool, str, str]:
        ep = ["--entrypoint", p.entrypoint] if p.entrypoint else []
        if p.check:
            c = self._run(f"{self.tag}-{lid}-check", ["--network", "none", "--cpus", "1", "--memory", "256m",
                                                      *p.mounts, *ep, p.image, *p.check], timeout=60)
            if c.returncode != 0:
                return False, server_error(c.stdout + c.stderr), ""
        name = f"{self.tag}-{lid}-srv"
        self.names.add(name)
        r = docker(["run", "-d", "--name", name, "--network", self.net, "--network-alias", "srv",
                    "--cpus", "1", "--memory", "256m", *p.mounts, *ep, p.image, *p.command], timeout=60)
        if r.returncode != 0:
            return False, r.stderr.strip(), name
        deadline = time.time() + 10
        while time.time() < deadline:
            time.sleep(0.5)
            st = docker(["inspect", name, "--format", "{{.State.Running}}"]).stdout.strip()
            logs = docker(["logs", name])
            if st != "true":
                return False, server_error(logs.stdout + logs.stderr), name
            if not p.ready or p.ready in logs.stdout + logs.stderr:
                time.sleep(0.5)
                return True, "", name
        return True, "", name

    def one(self, lid: str, listener: dict) -> dict:
        rd = self.base / lid
        rd.mkdir()
        p = servers.plant(listener, rd, self.certs)
        started, err, srv = self._start(lid, p)
        try:
            if not started:
                raise RuntimeError(f"{lid}: server refused its configuration: {err}")
            j = job() | {"port": p.port}
            (rd / "job.json").write_text(json.dumps(j))
            ref = self._run(f"{self.tag}-{lid}-ref",
                            ["--network", self.net, "--cpus", "1", "--memory", "256m",
                             "-v", f"{PROBE}:/probe/probe.py:ro", "-v", f"{rd}/job.json:/job.json:ro",
                             servers.HARNESS_IMAGE, "python3", "/probe/probe.py", "/job.json"], timeout=900)
            try:
                out = json.loads(ref.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError) as e:
                raise RuntimeError(f"{lid}: reference client gave no result: {(ref.stdout + ref.stderr)[-800:]}") from e
            return observation(lid, listener, out, j)
        finally:
            if srv:
                self._rm(srv)

    def go(self, listeners: dict[str, dict], outdir: Path, only: set[str] | None = None) -> list[str]:
        self.certs = self.base / "certs"
        self.certs.mkdir()
        self._run(f"{self.tag}-certs", ["--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                                        "-v", f"{self.certs}:/x", servers.HARNESS_IMAGE, "sh", "-c", "cp /certs/* /x/"], 60)
        done = []
        try:
            docker(["network", "create", "--internal", self.net])
            for lid, lst in listeners.items():
                if only and lid not in only:
                    continue
                t0 = time.time()
                obs = self.one(lid, lst)
                (outdir / f"{lid}.json").write_text(json.dumps(obs, indent=1) + "\n")
                acc = obs["accepted"]
                self.log(f"{lid:<10} {lst['server']:<8} {time.time() - t0:5.1f}s  groups: "
                         + ",".join(g["name"] + "/" + "+".join(g["versions"]) for g in acc["group"])
                         + "  suites: " + ",".join(s["code"] for s in acc["cipher_suite"]))
                done.append(lid)
        finally:
            for n in list(self.names):
                self._rm(n)
            docker(["network", "rm", self.net], timeout=30)
            shutil.rmtree(self.base, ignore_errors=True)
        return done
