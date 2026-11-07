<!-- One row per pull request. See CONTRIBUTING.md. -->

## What this changes

- [ ] New row `SL-NNNN` (axis: quantum / weak / defect)
- [ ] Withdrawal or correction of `SL-NNNN`
- [ ] Scanner adapter or result
- [ ] Generator, schema or docs

Closes #

## Review checklist

Rows:

- [ ] **Primary source**: specification, registry, or the vendor's own documentation or source code, with URL, section and date read; a verbatim `quote` where it settles the question. Not a blog, tutorial, scanner rule set or model answer.
- [ ] `literal` is one line and occurs verbatim in `context_template`; the template is the smallest valid file and contains no other cryptographic form.
- [ ] **Decoy**: a decoy is added where one is natural; a decoy's template contains no real use, and `decoy_class` says why it is not one.
- [ ] Weak row: `weakness` has `status`, `anchor` (standard and section) and `quote`. Defect row: `row_kind: defect`, `defect.cwe`, and for a positive row a `right_template` without the literal.
- [ ] `status` is `verified-source` or `verified-run`; otherwise the row belongs in `candidates/`.
- [ ] No row is deleted: a wrong row is `withdrawn` with `withdrawn_reason` and `withdrawn_at`; ids are never reused.

Adapters and results:

- [ ] Results in `results/` are produced by the generator, unedited, and include the scanner's version string.

Always:

- [ ] `cd generator && python -m shorlist validate && cd .. && python -m pytest -q tests` passes locally.
- [ ] I agree that data is licensed under CC BY 4.0 and code under Apache-2.0.

A row is never rejected because a scanner, including the initiator's, does not recognise it. Every row needs two approving reviewers other than its author.
