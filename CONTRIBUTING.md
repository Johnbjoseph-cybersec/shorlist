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
