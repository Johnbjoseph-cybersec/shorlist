"""Load and check live/wire.yaml, and count it."""
from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

import yaml

WIRE = Path(__file__).resolve().parent / "wire.yaml"
KINDS = {"tls": {"group", "cipher_suite", "sigalg"},
         "ssh": {"kex", "hostkey", "cipher", "mac", "server_sig_alg"},
         "ike": {"ike_ke"}}
NOT_RUNNABLE = {"cloud", "appliance", "config_rejected", "not_attempted"}
NOT_SCORED = {"not_on_wire", "comment_decoy", "no_scanner"}
SERVERS = {"openssh", "nginx", "apache", "s_server", "strongswan"}


def load(path: Path = WIRE) -> dict:
    return yaml.safe_load(path.read_text())


def sha256(path: Path = WIRE) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def problems(wire: dict, forms: dict[str, dict]) -> list[str]:
    """Shape checks a reader can rely on. `forms` is id -> catalogue row."""
    errs = []
    srcs = set(wire["sources"])
    for rid, e in wire["rows"].items():
        if rid not in forms:
            errs.append(f"{rid}: not in forms/")
            continue
        if e["protocol"] not in KINDS:
            errs.append(f"{rid}: protocol {e['protocol']!r}")
        if "not_runnable" in e and e["not_runnable"] not in NOT_RUNNABLE:
            errs.append(f"{rid}: not_runnable {e['not_runnable']!r}")
        if "not_scored" in e and e["not_scored"] not in NOT_SCORED:
            errs.append(f"{rid}: not_scored {e['not_scored']!r}")
        if ("not_runnable" in e or "not_scored" in e) and not e.get("reason"):
            errs.append(f"{rid}: a not_runnable / not_scored row needs a reason")
        if "not_runnable" not in e or e["not_runnable"] == "config_rejected":
            if e.get("server") not in SERVERS:
                errs.append(f"{rid}: server {e.get('server')!r}")
        runnable = "not_runnable" not in e and "not_scored" not in e
        if runnable and not e.get("items"):
            errs.append(f"{rid}: a scored row needs items")
        for it in e.get("items", []):
            if it["kind"] not in KINDS[e["protocol"]]:
                errs.append(f"{rid}: kind {it['kind']!r} for {e['protocol']}")
            if it["expect"] not in ("seen", "not_seen"):
                errs.append(f"{rid}: expect {it['expect']!r}")
            for s in (it["source"] if isinstance(it["source"], list) else [it["source"]]):
                if s not in srcs:
                    errs.append(f"{rid}: source {s!r} not under sources")
            if not it.get("quote"):
                errs.append(f"{rid}: item {it['name']} has no quote")
        if forms[rid]["negative"] and runnable and any(i["expect"] == "seen" for i in e["items"]):
            errs.append(f"{rid}: a decoy (negative) row may only have not_seen items")
        if not forms[rid]["negative"] and runnable and any(i["expect"] == "not_seen" for i in e["items"]):
            errs.append(f"{rid}: a positive row with not_seen items")
    return errs


def stats(wire: dict) -> dict:
    rows = wire["rows"].values()
    status = Counter()
    for e in rows:
        status["not_runnable: " + e["not_runnable"] if "not_runnable" in e else
               "not_scored: " + e["not_scored"] if "not_scored" in e else "scored"] += 1
    return {
        "rows": len(wire["rows"]),
        "with_items": sum(bool(e.get("items")) for e in rows),
        "items": sum(len(e.get("items", [])) for e in rows),
        "by_status": dict(sorted(status.items())),
        "by_server": dict(sorted(Counter(e.get("server", "-") for e in rows).items())),
        "by_protocol": dict(sorted(Counter(e["protocol"] for e in rows).items())),
        "scored_positive": sum(1 for e in rows if "not_runnable" not in e and "not_scored" not in e and not e["negative"]),
        "scored_decoy": sum(1 for e in rows if "not_runnable" not in e and "not_scored" not in e and e["negative"]),
    }
