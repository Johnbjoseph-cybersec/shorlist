"""Plant each runnable row as a live server, check the wire with the reference client, run the
scanners against it, and score.

Per row, at most two containers run at once, each with --cpus 1:
    1. config test in the server image, --network none (sshd -t, nginx -t, httpd -t)
    2. the server, detached, on a fresh `docker network create --internal` network, alias `srv`
    3. the reference client (live/probe.py in the harness image), same network; it also captures the
       pcap of one broad handshake for the passive adapter
    4. each active scanner in turn, same network
    5. the server is removed; the passive adapter (Zeek) reads the pcap with --network none
Every container is started with --name and removed with `docker rm -f` in a finally block, as is the
network. Nothing leaves the internal network: it has no route out.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import platform
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__
from ..catalogue import ROOT, catalogue_sha256, catalogue_version, load
from . import scoring, servers, wire as wiremod
from .scanners import SCANNERS

PROBE = Path(__file__).resolve().parent / "probe.py"
HARNESS_DOCKERFILE = ROOT / "containers" / "live" / "Dockerfile"
RESULT_FORMAT = "live-0.1"


def docker(args: list[str], timeout: int = 120, name: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        if name:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return subprocess.CompletedProcess(e.cmd, 124, e.stdout or "", (e.stderr or "") + f"\n<timeout after {timeout}s>")


def server_error(text: str) -> str:
    """The server's own error lines, without timestamps or image entrypoint chatter (stable across runs)."""
    keep = []
    for line in text.splitlines():
        if line.startswith("/docker-entrypoint") or ": info: " in line:
            continue
        line = re.sub(r"^\[[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d [\d:.]+ \d{4}\] ", "", line)
        line = re.sub(r"^\d{4}/\d\d/\d\d [\d:]+ ", "", line)
        line = re.sub(r"\[pid \d+(:tid \d+)?\] |\d+#\d+: ", "", line)
        if re.search(r"emerg|error|bad |unsupported|failed|fatal|invalid", line, re.I):
            keep.append(line.strip())
    return " / ".join(keep) or text.strip()[-500:]


def image_id(ref: str) -> str:
    p = docker(["image", "inspect", ref, "--format", "{{.Id}}"])
    return p.stdout.strip() or f"missing: {ref}"


class Run:
    def __init__(self, adapters: list[str], timeout: int = 300, keep: Path | None = None, log=print):
        self.adapters = [SCANNERS[a] for a in adapters]
        self.timeout = timeout
        self.keep = keep
        self.log = log
        self.tag = f"shorlist-live-{os.getpid()}"
        self.net = self.tag
        self.base = Path(tempfile.mkdtemp(prefix="shorlist-live-"))
        self.names: set[str] = set()

    # ---------- containers ----------
    def _run(self, name: str, args: list[str], timeout: int) -> subprocess.CompletedProcess:
        self.names.add(name)
        try:
            return docker(["run", "--rm", "--name", name, *args], timeout=timeout, name=name)
        finally:
            docker(["rm", "-f", name], timeout=30)
            self.names.discard(name)

    def _start_server(self, rid: str, p: servers.Plant) -> tuple[bool, str, str]:
        """(started, error, name). The config test runs first, in the same image, without network."""
        if p.check:
            ep = ["--entrypoint", p.entrypoint] if p.entrypoint else []
            c = self._run(f"{self.tag}-{rid}-check", ["--network", "none", "--cpus", "1", "--memory", "256m",
                                                      *p.mounts, *ep, p.image, *p.check], timeout=60)
            if c.returncode != 0:
                return False, server_error(c.stdout + c.stderr), ""
        name = f"{self.tag}-{rid}-srv"
        self.names.add(name)
        ep = ["--entrypoint", p.entrypoint] if p.entrypoint else []
        r = docker(["run", "-d", "--name", name, "--network", self.net, "--network-alias", "srv",
                    "--cpus", "1", "--memory", "256m", *p.mounts, *ep, p.image, *p.command], timeout=60)
        if r.returncode != 0:
            return False, r.stderr.strip(), name
        deadline = time.time() + 10
        while time.time() < deadline:
            time.sleep(0.5)
            st = docker(["inspect", name, "--format", "{{.State.Running}}"]).stdout.strip()
            logs = docker(["logs", name])
            text = logs.stdout + logs.stderr
            if st != "true":
                return False, server_error(text), name
            if not p.ready or p.ready in text:
                time.sleep(0.5)
                return True, "", name
        return True, "", name  # running, no ready line seen: let the reference client decide

    def _stop(self, name: str):
        if name:
            docker(["rm", "-f", name], timeout=30)
            self.names.discard(name)

    # ---------- one row ----------
    def row(self, rid: str, form: dict, w: dict) -> dict:
        rd = self.base / rid
        rd.mkdir()
        (rd / "out").mkdir()
        (rd / "out").chmod(0o777)
        rec: dict = {"status": None, "reference": [], "scanners": {}}
        p = servers.plant(form, w, rd, self.certs)
        started, err, srv = self._start_server(rid, p)
        try:
            if not started:
                rec.update(status="config_rejected", error=err)
                return rec
            rec["status"] = "started"
            job = {"protocol": w["protocol"], "host": "srv", "port": p.port, "items": w["items"],
                   "pcap": "/out/handshake.pcap" if any(a.passive for a in self.adapters) else None}
            (rd / "job.json").write_text(json.dumps(job))
            ref = self._run(f"{self.tag}-{rid}-ref",
                            ["--network", self.net, "--cpus", "1", "--memory", "256m", "--cap-add", "NET_RAW",
                             "--cap-add", "NET_ADMIN", "-v", f"{PROBE}:/probe/probe.py:ro", "-v", f"{rd}/job.json:/job.json:ro",
                             "-v", f"{rd}/out:/out", servers.HARNESS_IMAGE, "python3", "/probe/probe.py", "/job.json"],
                            timeout=180)
            (rd / "reference.txt").write_text(ref.stdout + ref.stderr)
            try:
                refj = json.loads(ref.stdout.strip().splitlines()[-1])
                rec["reference"] = refj["items"]
                rec["reference_extra"] = {k: v for k, v in refj.items() if k not in ("items", "protocol")}
            except (ValueError, IndexError, KeyError):
                rec["reference_error"] = (ref.stdout + ref.stderr)[-1000:]
            for a in self.adapters:
                if w["protocol"] not in a.protocols or a.passive:
                    continue
                rec["scanners"][a.name] = self._scan(a, rid, w, p, rd)
        finally:
            self._stop(srv)
        for a in self.adapters:
            if a.passive and w["protocol"] in a.protocols:
                rec["scanners"][a.name] = self._scan(a, rid, w, p, rd)
        return rec

    def _scan(self, a, rid: str, w: dict, p: servers.Plant, rd: Path) -> dict:
        od = rd / "out" / a.name
        od.mkdir()
        od.chmod(0o777)
        if a.passive:
            pcap = rd / "out" / "handshake.pcap"
            if not pcap.exists():
                return {"error": "no pcap"}
            shutil.copy(pcap, od / "handshake.pcap")
            os.chmod(od / "handshake.pcap", 0o644)
            args = ["--network", "none", "--cpus", "1", "--memory", "512m", "-v", f"{od}:/out", a.image,
                    *a.argv(w["protocol"], "srv", p.port)]
        else:
            args = ["--network", self.net, "--cpus", "1", "--memory", "512m", "-v", f"{od}:/out", a.image,
                    *a.argv(w["protocol"], "srv", p.port)]
        t0 = time.time()
        r = self._run(f"{self.tag}-{rid}-{a.name.replace('.', '')}", args, timeout=self.timeout)
        (od / "stdout.txt").write_text(r.stdout)
        (od / "stderr.txt").write_text(r.stderr)
        out = {"exit": r.returncode, "seconds": round(time.time() - t0, 1)}
        if r.returncode == 124:
            out["error"] = f"timeout after {self.timeout}s"
            return out
        try:
            out["observed"] = sorted([list(o) for o in a.parse(w["protocol"], r.stdout, od)])
        except Exception as e:  # noqa: BLE001 - any unparseable output is a scanner_error, recorded
            out["error"] = f"{type(e).__name__}: {e}; stderr: {r.stderr[-300:]}"
        return out

    # ---------- whole run ----------
    def versions(self) -> dict:
        v = {}
        for a in self.adapters:
            r = self._run(f"{self.tag}-version-{a.name.replace('.', '')}", ["--network", "none", a.image, *(a.version_argv or [])],
                          timeout=60)
            v[a.name] = a.version(r.stdout + r.stderr)
        return v

    def go(self, root: Path = ROOT, only: set[str] | None = None, server: set[str] | None = None) -> list[dict]:
        wire = wiremod.load()
        forms = {r["id"]: r for r in load(root)}
        errs = wiremod.problems(wire, forms)
        if errs:
            raise ValueError("wire.yaml invalid:\n  " + "\n  ".join(errs))
        self.certs = self.base / "certs"
        self.certs.mkdir()
        self._run(f"{self.tag}-certs", ["--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                                        "-v", f"{self.certs}:/x", servers.HARNESS_IMAGE, "sh", "-c", "cp /certs/* /x/"], 60)
        raw: dict[str, dict] = {}
        try:
            scanner_versions = self.versions()
            docker(["network", "create", "--internal", self.net])
            for rid, w in wire["rows"].items():
                if only and rid not in only:
                    continue
                if server and w.get("server") not in server:
                    continue
                if "not_runnable" in w and w["not_runnable"] != "config_rejected" or "not_scored" in w:
                    continue
                if not any(w["protocol"] in a.protocols for a in self.adapters):
                    continue
                raw[rid] = self.row(rid, forms[rid], w)
                err = (raw[rid].get("error") or "").strip().splitlines()
                self.log(f"{rid}  {w['server']:<8} {raw[rid]['status']:<15} " + "  ".join(
                    f"{k}:{'err' if 'error' in v else len(v.get('observed', []))}" for k, v in raw[rid]["scanners"].items())
                    + (f"  {err[-1][:110]}" if err else ""))
        finally:
            for n in list(self.names):
                docker(["rm", "-f", n], timeout=30)
            docker(["network", "rm", self.net], timeout=30)
            if self.keep:
                if self.keep.exists():
                    shutil.rmtree(self.keep)
                shutil.copytree(self.base, self.keep, ignore=shutil.ignore_patterns("*.pem", "*.key"))
            shutil.rmtree(self.base, ignore_errors=True)
        return [self.result(a, wire, forms, raw, scanner_versions[a.name], root, only, server) for a in self.adapters]

    def result(self, a, wire, forms, raw, scanner_version, root, only, server) -> dict:
        scored = []
        for rid, w in wire["rows"].items():
            if w["protocol"] not in a.protocols:
                continue
            if only and rid not in only or server and w.get("server") not in server:
                continue
            run = raw.get(rid, {})
            sc = run.get("scanners", {}).get(a.name, {})
            obs = {tuple(o) for o in sc["observed"]} if "observed" in sc else None
            runinfo = {"status": run.get("status"), "error": run.get("error"), "reference": run.get("reference"),
                       "scanner_error": sc.get("error")}
            s = scoring.score(w, runinfo, obs)
            s.update(id=rid, server=w.get("server", "—"), product=w["product"], family=forms[rid]["family"],
                     negative=w["negative"], literal=w["literal"], protocol=w["protocol"])
            if run.get("reference"):
                s["reference"] = run["reference"]
            if sc:
                s["scanner_exit"], s["scanner_seconds"] = sc.get("exit"), sc.get("seconds")
            scored.append(s)
        # The fingerprint takes the registry digests and the harness Dockerfile's sha256, which are the same on
        # every machine; the locally built harness image ID is recorded beside it but not fingerprinted.
        images = {"harness_dockerfile_sha256": hashlib.sha256(HARNESS_DOCKERFILE.read_bytes()).hexdigest(),
                  **{k: v for k, v in servers.IMAGES.items() if k not in ("openssh", "s_server")}, "scanner": a.image}
        w_sha, c_sha = wiremod.sha256(), catalogue_sha256(root)
        summ = scoring.summary(scored)
        version = catalogue_version(root)
        p, d = summ["positive"], summ["decoys"]
        return {
            "result_format": RESULT_FORMAT,
            "axis": "network",
            "statement": (f"Of {p['n']} positive rows planted as live servers from ShorList {version}, {scanner_version} "
                          f"reports the expected wire item for {p['hit']}; of {d['n']} removal/ban decoys it reports "
                          f"{d['false_alarm']} as offered. Rows the reference client could not confirm on the wire are "
                          f"not scored."
                          + (" Passive: only the values negotiated in one broad handshake by the reference client are "
                             "visible to it, not the server's offer." if a.passive else "")),
            "catalogue": {"name": "ShorList", "version": version, "sha256": c_sha},
            "wire": {"sha256": w_sha, **wiremod.stats(wire)},
            "generator": {"name": "shorlist", "version": __version__},
            "scanner": {"adapter": a.name, "image": a.image, "tag": a.tag, "version": scanner_version,
                        "protocols": list(a.protocols), "passive": a.passive},
            "harness": {"images": images, "harness_image_id": image_id(servers.HARNESS_IMAGE), "server_versions": servers.VERSIONS,
                        "harness_image_versions": docker(["run", "--rm", "--network", "none", servers.HARNESS_IMAGE,
                                                          "cat", "/versions.txt"]).stdout.split("\n")},
            "selection": {"rows": sorted(only) if only else "all", "servers": sorted(server) if server else "all"},
            "summary": summ,
            "positive_controls": scoring.controls(a, scored),
            "by_server": scoring.table(scored, "server"),
            "by_family": scoring.table(scored, "family"),
            "rows": scored,
            "fingerprint": scoring.fingerprint(w_sha, c_sha, __version__, scanner_version, images, scored),
            "fingerprint_rule": "sha256(canonical JSON {wire_sha256, catalogue_sha256, generator_version, scanner_version, images, rows:[[id,outcome,reason]...]})",
            "run": {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "python": platform.python_version(), "platform": platform.platform()},
            "raw": {rid: {"status": r.get("status"), "error": r.get("error"), "reference_extra": r.get("reference_extra"),
                          "scanner": r.get("scanners", {}).get(a.name)} for rid, r in raw.items()},
        }
