# Security

Report a vulnerability privately through GitHub: **Security → Report a vulnerability**
on this repository. Please do not open a public issue for it.

In scope: the generator (`generator/`), its adapters and containers, and the GitHub workflows.
A wrong row is not a security issue; report it with the *Correction to a row* form.

The key material in `forms/` (the PEM rows SL-3596 to SL-3604, SL-3616 and SL-3637 to SL-3646) are throwaway test keys generated for the
catalogue, with no use anywhere else. They are not leaked secrets; see
[Test keys](README.md#test-keys).
