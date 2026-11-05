# Candidates

Proposed forms that are **not yet verified** against a primary source, or verified only
by someone's word. They are not part of the catalogue, are not measured, and are not
counted in any result.

A candidate becomes a row when someone checks it against a primary source (or runs the
product) and opens a pull request moving it into `forms/` with `status: verified-source`
or `verified-run`, under the rules in [CONTRIBUTING.md](../CONTRIBUTING.md).

Format: the same YAML as a row, with `status: candidate` and a `notes` field saying what
is still unchecked. Candidates are not validated against the schema.
