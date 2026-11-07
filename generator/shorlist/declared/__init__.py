"""ShorList declaration axis (PLAN.md section 12): a supplier's CycloneDX 1.7 declaration of one TLS
listener beside the set that listener ACCEPTED when a reference client offered each candidate alone,
and the one verdict CycloneDX 1.7 allows for the pair: consistent | undeclared | overclaimed |
parameter_mismatch. It measures the tools a firm would use to check a supplier's CBOM, not the product.

    rows/*.yaml          one pair each (declaration, listener, verdict, focus, resolves_to)
    listeners.yaml       the live listeners (nginx, Apache httpd, openssl s_server)
    observations/*.json  their captured accepted sets (`declared --capture`, docker)
    reference.py         the positive control: a plain implementation of S1-S10, NOT a scanner
    adapters.py          sbom-tools 0.3.0, cyclonedx-cli 0.33.1 diff, and the reference
"""
