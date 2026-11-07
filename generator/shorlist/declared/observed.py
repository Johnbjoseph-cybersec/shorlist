"""The observed CBOM a tool under test is given beside the declaration. Built from a captured
observation in one fixed, neutral way:

  - metadata.component: {type: application, name: "observed listener <listener id>", bom-ref: observed}
  - one `protocol` cryptographic-asset per TLS version with at least one accepted item, named
    "TLSv1.3" / "TLSv1.2" (the names every declaration in rows/ uses for its in-scope components, so
    that pairing components by name is not what is tested: this favours the tools), bom-ref
    observed/tls13 / observed/tls12, protocolProperties {type: tls, version}
  - cipherSuites[]: every suite accepted in that version, `name` = the IANA name, `identifiers` =
    ["0xC0,0x30"] (the IANA CSV form, one string)
  - tlsGroups: every group accepted in that version, IANA names, on every suite of that version
    (scope rule S5 read backwards: the union is put where 1.7 has a field for it)
  - no algorithm components: the wire shows code points, not algorithms. A cdxgen-tracebom-shaped
    observation (a hybrid written as its two halves) is NOT used, see OTCHET "not done".
It validates against the CycloneDX 1.7.2 schema (checked by validate).
"""
from __future__ import annotations


def ident(code: str) -> str:
    return f"0x{code[2:4]},0x{code[4:6]}"


def build(obs: dict) -> dict:
    comps = []
    for v in ("1.3", "1.2"):
        suites = [s for s in obs["accepted"]["cipher_suite"] if v in s["versions"]]
        groups = [g["name"] for g in obs["accepted"]["group"] if v in g["versions"]]
        if not suites and not groups:
            continue
        cs = [{"name": s["name"], "identifiers": [ident(s["code"])], **({"tlsGroups": groups} if groups else {})}
              for s in suites] or [{"tlsGroups": groups}]
        comps.append({"type": "cryptographic-asset", "name": f"TLSv{v}", "bom-ref": f"observed/tls{v.replace('.', '')}",
                      "cryptoProperties": {"assetType": "protocol",
                                           "protocolProperties": {"type": "tls", "version": v, "cipherSuites": cs}}})
    return {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "metadata": {"component": {"type": "application", "name": f"observed listener {obs['listener']}",
                                       "bom-ref": "observed"}},
            "components": comps}
