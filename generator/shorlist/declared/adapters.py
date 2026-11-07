"""Adapters: run a tool on (declared CBOM, observed CBOM) and translate its own output into findings.

A finding is {"verdict": undeclared | overclaimed | parameter_mismatch, "category": group | cipher_suite,
"element": {...}, "tool_says": <the tool's own words>}. No finding in a category = the tool says
`consistent` for it. An adapter translates vocabulary only: it never resolves a spelling (that is
the tool's job, and the scorer accepts any spelling that denotes the focus code point).

Both third-party tools are component-level differs, so the translation is the same:
    component in the observed CBOM only  (tool: added)    -> undeclared, for every item it carries
    component in the declared CBOM only  (tool: removed)  -> overclaimed, for every item it carries
The items a reported component carries are read from the document the tool was given, by the
bom-ref the tool reports (cyclonedx-cli's echo of a component drops 1.7 fields such as tlsGroups):
    a protocol component: each cipherSuites[] entry (category cipher_suite) and each tlsGroups
        string (category group)
    an algorithm component with primitive key-agree, kem or combiner: one group item (scope rule S5)
    any other component: nothing in the compared categories
sbom-tools also reports `modified` components with field-level changes; a `crypto_algorithm`
(algorithmFamily) change on a group-carrying component is taken as parameter_mismatch; every other
field change is kept in `unmapped` and is not a finding.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from . import reference

GROUP_PRIMITIVES = ("key-agree", "kem", "combiner")


def _by_ref(bom: dict) -> dict[str, dict]:
    out = {}

    def walk(cs):
        for c in cs or []:
            if c.get("bom-ref"):
                out[c["bom-ref"]] = c
            walk(c.get("components"))
    walk(bom.get("components"))
    return out


def items_of(comp: dict) -> list[tuple[str, dict]]:
    """(category, element) for every compared item a component carries."""
    cp = comp.get("cryptoProperties") or {}
    out = []
    if cp.get("assetType") == "protocol":
        for cs in (cp.get("protocolProperties") or {}).get("cipherSuites", []):
            if cs.get("name") or cs.get("identifiers"):
                out.append(("cipher_suite", {"ref": comp.get("bom-ref"), "name": cs.get("name"),
                                             "identifiers": cs.get("identifiers")}))
            for g in cs.get("tlsGroups", []):
                el = {"ref": comp.get("bom-ref"), "value": g}
                if ("group", el) not in out:
                    out.append(("group", el))
    elif cp.get("assetType") == "algorithm" and (cp.get("algorithmProperties") or {}).get("primitive") in GROUP_PRIMITIVES:
        out.append(("group", {"ref": comp.get("bom-ref"), "name": comp.get("name")}))
    return out


def component_findings(verdict: str, comp: dict, doc: dict, says: str) -> list[dict]:
    full = _by_ref(doc).get(comp.get("bom-ref") or comp.get("id"), comp)
    return [{"verdict": verdict, "category": cat, "element": el, "tool_says": says} for cat, el in items_of(full)]


class Tool:
    name = ""
    image = ""
    tag = ""
    version_args: list[str] = []
    docker = ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--memory", "512m", "--cpus", "1", "--pids-limit", "256"]

    def args(self) -> list[str]:
        raise NotImplementedError

    def command(self) -> str:
        """The recorded command line, without host paths."""
        return " ".join(self.docker + ["-v", "<pair>:/in:ro", self.image] + self.args())

    def version(self) -> str:
        p = subprocess.run(self.docker + [self.image] + self.version_args, capture_output=True, text=True, timeout=60)
        return (p.stdout + p.stderr).strip().splitlines()[0] if (p.stdout + p.stderr).strip() else f"unknown ({self.image})"

    def image_id(self) -> str:
        p = subprocess.run(["docker", "image", "inspect", self.image, "--format", "{{.Id}}"], capture_output=True, text=True)
        return p.stdout.strip() or f"missing: {self.image}"

    def run(self, declared: dict, observed: dict, keep: Path | None = None) -> dict:
        with tempfile.TemporaryDirectory(prefix="shorlist-decl-pair-") as d:
            dp = Path(d)
            dp.chmod(0o755)
            for n, doc in (("declared.cdx.json", declared), ("observed.cdx.json", observed)):
                (dp / n).write_text(json.dumps(doc, indent=1))
                (dp / n).chmod(0o644)
            p = subprocess.run(self.docker + ["-v", f"{dp}:/in:ro", self.image] + self.args(),
                               capture_output=True, text=True, timeout=300)
        raw = {"exit": p.returncode, "stdout": p.stdout, "stderr": p.stderr[-2000:]}
        if keep:
            keep.mkdir(parents=True, exist_ok=True)
            (keep / f"{self.name}.stdout.txt").write_text(p.stdout)
            (keep / f"{self.name}.stderr.txt").write_text(p.stderr)
        return raw

    def parse(self, stdout: str, declared: dict, observed: dict) -> dict:
        raise NotImplementedError


class SbomTools(Tool):
    """sbom-tools 0.3.0 `diff OLD NEW -o json`, OLD = the declaration, NEW = the observation."""
    name = "sbom-tools"
    image = "shorlist-sbom-tools:0.3.0"
    tag = "0.3.0"
    version_args = ["--version"]

    def args(self):
        return ["diff", "/in/declared.cdx.json", "/in/observed.cdx.json", "-o", "json", "--offline", "--no-config", "-q"]

    def parse(self, stdout, declared, observed):
        d = json.loads(stdout[stdout.index("{"):])
        comps = (d.get("reports") or {}).get("components") or {}
        findings, unmapped = [], []
        for c in comps.get("added", []):
            findings += component_findings("undeclared", {"bom-ref": c.get("id"), "name": c.get("name")}, observed,
                                           f"added component {c.get('name')!r} ({c.get('id')})")
        for c in comps.get("removed", []):
            findings += component_findings("overclaimed", {"bom-ref": c.get("id"), "name": c.get("name")}, declared,
                                           f"removed component {c.get('name')!r} ({c.get('id')})")
        for c in comps.get("modified", []):
            for fc in c.get("field_changes", []):
                old = _by_ref(declared).get(c.get("id")) or {}
                if fc.get("field") == "crypto_algorithm" and any(cat == "group" for cat, _ in items_of(old)):
                    findings.append({"verdict": "parameter_mismatch", "category": "group",
                                     "element": {"ref": c.get("id"), "name": c.get("name"),
                                                 "declared": fc.get("old_value"), "observed": fc.get("new_value")},
                                     "tool_says": f"modified {c.get('name')!r}: {fc}"})
                else:
                    unmapped.append({"component": c.get("name"), "id": c.get("id"), "change": fc})
        return {"findings": findings, "unmapped": unmapped, "summary": d.get("summary")}


class CycloneDxCli(Tool):
    """cyclonedx-cli 0.33.1 `diff FROM TO --component-versions --output-format json`, FROM = the
    declaration, TO = the observation. It pairs components by name (and group/version) only."""
    name = "cyclonedx-cli"
    image = "shorlist-cyclonedx-cli:0.33.1"
    tag = "0.33.1"
    version_args = ["--version"]

    def args(self):
        return ["diff", "/in/declared.cdx.json", "/in/observed.cdx.json", "--from-format", "json", "--to-format", "json",
                "--output-format", "json", "--component-versions"]

    def version(self) -> str:
        v = super().version()
        return "cyclonedx-cli " + re.sub(r"\+.*", "", v) if re.match(r"\d", v) else v

    def parse(self, stdout, declared, observed):
        d = json.loads(stdout[stdout.index("{"):])
        findings = []
        for name, cv in (d.get("componentVersions") or {}).items():
            for c in cv.get("added", []):
                findings += component_findings("undeclared", c, observed, f"componentVersions[{name!r}].added")
            for c in cv.get("removed", []):
                findings += component_findings("overclaimed", c, declared, f"componentVersions[{name!r}].removed")
        return {"findings": findings, "unmapped": []}


class Reference:
    """The positive control (reference.py), run in process: NOT a scanner, not a tool under test."""
    name = "reference"
    image = "-"
    tag = "-"

    def command(self):
        return "in process: shorlist.declared.reference.compare (" + reference.LABEL + ")"

    def version(self):
        from .. import __version__
        return f"shorlist reference comparator {__version__}"

    def image_id(self):
        return "-"

    def compare(self, declared: dict, obs: dict, category: str) -> dict:
        r = reference.compare(declared, obs, category)
        f = []
        if r["verdict"] == "parameter_mismatch":
            f.append({"verdict": "parameter_mismatch", "category": category,
                      "element": {"declared": r["focus"]["declared"], "observed": r["focus"]["observed"]},
                      "tool_says": f"parameter_mismatch in family {r['focus']['family']}"})
        else:
            f += [{"verdict": "undeclared", "category": category, "element": {"value": c}, "tool_says": "accepted, not declared"}
                  for c in r["undeclared"]]
            f += [{"verdict": "overclaimed", "category": category, "element": {"value": c}, "tool_says": "declared, refused"}
                  for c in r["overclaimed"]]
        return {"findings": f, "unmapped": [], "reference": r}


TOOLS = {t.name: t for t in (SbomTools, CycloneDxCli, Reference)}
