# Security

Report a vulnerability privately through GitHub: **Security → Report a vulnerability**
on this repository. Please do not open a public issue for it.

In scope: the generator (`generator/`), its adapters and containers, and the GitHub workflows.
A wrong row is not a security issue; report it with the *Correction to a row* form.

The private keys in `forms/` (PEM and JWK rows) are throwaway test keys generated for the
catalogue, with no use anywhere else. They are not leaked secrets; see
[Test keys](README.md#test-keys).
