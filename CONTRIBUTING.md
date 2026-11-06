# Contributing to ShorList

Rows are added by pull request. Anyone may propose one; a row written by a scanner vendor
is as welcome as any other and is reviewed by the same rules.

## Adding a row

1. Take the next free id (`SL-NNNN`); ids are never reused, even for withdrawn rows.
2. Copy an existing file in `forms/` of the same `form_kind` and edit it. File name = id.
3. `literal` is the exact text of the form, on one line, and occurs verbatim in
   `context_template`.
4. `context_template` is the **smallest valid file** in which the form stands, planted
   under `context_filename`. It contains no other cryptographic form. A decoy's template
   in particular must not contain a real use (no import of the crypto module, no other
   algorithm on any line), or the row cannot be scored.
5. `expected` is what a correct scanner reports for the literal's line: the family from
   [`schema/families.yaml`](schema/families.yaml), the role, and the key size, or
   `undetermined` where the line does not pin it. For a decoy, `expected` is what a scanner
   would *wrongly* report, and `decoy_class` says why it is not a use.
6. `source` lists at least one **primary source**: the specification, registry, or the
   vendor's own documentation or source code — not a blog, a tutorial, a scanner's rule
   set or a model's answer. Each entry has the URL, the section, and the date you read it;
   add a short verbatim `quote` where it settles the question.
7. `status`:
   - `verified-source` — you checked the form against the primary source;
   - `verified-run` — you also ran the product or library and saw it accept the form.

   If you have neither, the row is a **candidate**: put it in `candidates/` instead.
8. Run locally:

   ```sh
   pip install -r requirements.txt -r requirements-dev.txt
   cd generator && python -m shorlist validate && cd .. && python -m pytest -q tests
   ```

CI runs the same checks. It also runs qrp-mcp on the catalogue and posts the result as
information. **That run never blocks a row.** A form no scanner recognises is exactly the
kind of row the catalogue exists for.

## Weak rows and defect rows

Since v0.2 the catalogue is scored on three axes, reported apart. A scanner gains or loses
nothing on the quantum axis for a weak or a defect row, and the headline figure is the
quantum axis only.

- **quantum** — every row above: a Shor-vulnerable or post-quantum family.
- **weak** — a row with `weakness` (`status`, `anchor`, `quote`): a `classically_weak`
  family (SHA-1, MD5, 3DES, RC4 …) or a weak parameter of a quantum family (RSA-1024).
  The anchor is the standard that disallows or deprecates it, e.g. NIST SP 800-131A Rev. 2.
  A `classically_weak` family without `weakness` is rejected.
- **defect** — `row_kind: defect`: a misuse, not an algorithm. `context_template` is the
  wrong code and the literal is the defective line; `right_template` is the same file,
  fixed, and must not contain the literal. `defect.cwe` is what a scanner must report on
  the literal's line; `defect.taxonomy` may name the same class in other benchmarks, as a
  reference only. A scanner that reports any CWE on the fixed file raises a false alarm.
  `defect_only` families (AES, HMAC, RNG …) are allowed only in defect rows.

Write templates for defect rows yourself, from the description of the class. Copy a
template from another benchmark only when its licence allows it, and cite it in `source`.

## Review

- Every row needs **two approving reviewers** other than its author before it is merged.
  Reviewers check the source (does it say what the row says?), the template (is it
  minimal, does it contain nothing else?), and `expected`.
- Reviewers add themselves to `reviewed_by`.
- The initiator's affiliation (see *Conflict of interest* in the README) is not a reason to
  accept or to reject a row. Reviews from people unaffiliated with it are sought on purpose.

## Correcting or withdrawing a row

A row is **never deleted**. If it is wrong, set `status: withdrawn`, add
`withdrawn_reason` and `withdrawn_at`, and keep the rest as it was. Withdrawn rows are
excluded from measurement but stay in the catalogue, so earlier results remain
interpretable and the reason stays on record. A corrected form is a new row with a new id.

## Adding a scanner adapter

See *Adding a scanner* in the README and
[`generator/shorlist/adapters/base.py`](generator/shorlist/adapters/base.py). Results
committed to `results/` must be produced by the generator, unedited, and include the
scanner's version string.

## Licensing of contributions

By contributing you agree that rows and other catalogue data are licensed under
CC BY 4.0 and code under Apache-2.0, as in the repository's `LICENSE-DATA` and `LICENSE`.
