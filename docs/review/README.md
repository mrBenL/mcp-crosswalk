# Crosswalk review worksheet

`crosswalk-review.csv` lists all 77 mappings, one per row, with the control's own text from the vendored NIST
catalog next to the mapping's rationale. Use it to review each mapping, then apply your decisions to the crosswalk
YAML with `scripts/crosswalk_review.py`.

## Columns

| Column | Content |
|---|---|
| `risk_id`, `risk_title` | OWASP MCP Top 10 risk (2025 beta) |
| `framework`, `control_id`, `control_title` | `nist-800-53r5` or `nist-csf-2.0`, and the control or subcategory |
| `relationship`, `confidence` | Current values in the YAML |
| `rationale` | Current rationale, on one line |
| `check_ids` | Scanner checks linked to the mapping |
| `control_text` | The control statement or subcategory text from the vendored OSCAL catalog |
| `decision` | Fill in: `keep`, `change`, or `drop` |
| `new_relationship` | Fill in only when `decision` is `change`: `equal`, `subset_of`, `superset_of`, or `intersects_with` |
| `notes` | Fill in: your reasoning. Stays in the worksheet; not copied to the YAML |

Read each relationship as "the risk is ___ the control" (NIST OLIR convention). Definitions and examples are in
[`../methodology.md`](../methodology.md#relationship-direction-nist-olir-convention-nist-ir-8278). Cells that start with
`=`, `+`, `-`, or `@` are prefixed with `'` so spreadsheets show them as text.

## Steps

1. Fill in `decision` (and `new_relationship` for `change`) for each row. Leave a row blank if you have not
   decided yet. Save as CSV. A byte-order mark added by Excel is fine.
2. Preview: `uv run python scripts/crosswalk_review.py apply`. It prints what would change and which files would be
   marked reviewed. Nothing is written.
3. Apply: `uv run python scripts/crosswalk_review.py apply --write`. The script validates the result in a
   temporary copy first and writes nothing if validation fails.
4. Regenerate and check:
   - `uv run mcpxw crosswalk validate`
   - `uv run mcpxw crosswalk export --format md --out docs/crosswalk.md`
   - `uv run mcpxw crosswalk export --format csv --out docs/crosswalk.csv`
   - `uv run pytest -q`
5. Commit the YAML changes and the completed worksheet together, so the notes stay with the decisions.

## What the apply script does

- `keep`: no change.
- `change`: sets `relationship` to `new_relationship`. To change confidence, rationale, or check links, edit the
  YAML by hand.
- `drop`: removes the mapping.
- A risk file is set to `review_status: reviewed`, and its header comment to "Reviewed by the maintainer.", only
  when every mapping in that file has a decision. Files with any blank decision stay `draft`.
- Edits are made line by line, so the license comments and folded rationales are kept.

## Review record

The maintainer completed the review of all 77 mappings on 2026-10-31. This worksheet is the record of that review:
the `relationship` and `confidence` columns show the values before the review, and `decision`, `new_relationship`,
and `notes` show what changed and why. Two confidence changes made by hand after applying the worksheet (MCP01
`SC-28` and `PR.DS-01`, both to `low`) are noted in those rows. For a later review, run `export` to a new file
rather than overwriting this one.
