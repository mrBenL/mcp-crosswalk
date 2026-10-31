# mcp-crosswalk v0.2.0: Completion Report
Status: COMPLETE
Build dates: 2026-10-07 to 2026-10-07 (UTC; N0 commit e04ec25 through the N8 commit)

All N0 to N8 milestones are done. The full gate passed on a clean run after the review fixes. Of the 13
independent-review findings, 12 were fixed (one only in part) and 1 was rejected with a reason. Demos are in
`out/demo/` and `out/enrich-demo/` (git-ignored).

## What changed in 0.2.0
**N1: OWASP catalog versions and ID migration.** New `catalog/owasp-mcp/versions.yaml` (default `2025-beta`) and a
Pydantic migration format, exported as `schema/migration.schema.json` and `schema/versions.schema.json`.
`--catalog-version` was added to `scan`, `enrich`, and `crosswalk validate|show|export`. An unknown version exits 2
and lists the available ones. `mcpxw crosswalk migrate --to V --out DIR` writes renumbered copies, never in place.
It reports renamed, retired, and new-unmapped risks, and exits 1 while a gap remains. Scanner checks keep their
default-version IDs and are translated through the migration (D32). No real migration ships. The mechanism is
proven with a synthetic `2099-test` catalog in `tests/fixtures/catalog_versions/`, in which MCP07 becomes MCP11,
MCP08 is retired, and MCP12 is new. The live OWASP page still shows the 2025 edition in Phase 3 beta (D31).

**N2: Scanner gaps.** New check MCPXW-011 flags a cleartext `http://` URL to a non-loopback host inside a stdio
launcher. It is high severity when `mcp-remote`, `supergateway`, or `mcp-proxy` is named, medium otherwise; risk
MCP07; URL tokens are redacted. The four MCP07 mappings that cite MCPXW-007 now also cite MCPXW-011, and the
mapping count stays 77. VS Code `settings.json` servers are now parsed, under both the nested `"mcp": {"servers"}`
key and the flat `"mcp.servers"` key, JSONC included. Unrelated settings are never echoed. Four discovery locations
were added: the user settings file on macOS, Windows, and Linux, and `.vscode/settings.json`.

**N3: Federal context.** Five NIST OSCAL files are now vendored, with URL, date, and SHA-256 in `SOURCES.md`: the
LOW, MODERATE, HIGH, and PRIVACY baselines and SP 800-171 Rev 3. Each 800-53 control gets baseline membership and
"800-171r3 (derived via source 800-53 control)" links, both by exact ID match, excluding withdrawn requirements and
non-800-53 references. These fields are derived at runtime, never stored in YAML, and never counted as mappings.
They appear in `docs/crosswalk.md`/`.csv`, `crosswalk show`, report JSON (schema 1.1, additive), Markdown, and HTML.
No CMMC alignment is claimed anywhere; a test enforces this.

**N4: POA&M export.** `scan --format poam` writes `mcpxw-poam.csv`: the 18 specified columns, one row per finding,
sorted by severity then ID, UTF-8, RFC 4180, CRLF. Every CSV cell the tool writes, including `crosswalk export
--format csv`, is protected against formula injection. The README says "columns modeled on common POA&M fields".

**N5: `mcpxw enrich`.** Reads untrusted SARIF: 50 MB cap, strict JSON, structural SARIF check, no URI fetched or
opened. It extracts OWASP MCP IDs from every place the spec lists, then adds `properties["mcp-crosswalk"]` and
deduplicated `nist-800-53r5/…` and `nist-csf-2.0/…` tags. Everything else round-trips unchanged. It writes
`<stem>.enriched.sarif` plus optional JSON and Markdown summaries that carry the ID-numbering caution. Exit codes
are 0 and 2. All synthetic fixtures validate against the official SARIF 2.1.0 schema before and after enrichment.

**N6: Docs, positioning, version.** Version is 0.2.0, with a CHANGELOG entry. The README now leads with the
crosswalk, then `enrich`, then the scanner as a reference implementation, and adds a neutral "Related work"
section (the listed URLs were not fetched). `docs/methodology.md` gained sections on derived data, catalog
versioning, and enrich ID assumptions. `docs/threat-model.md` gained T11 (untrusted SARIF), T12 (CSV injection),
and T13 (migration path safety), each with tests. Generated docs and schemas were regenerated, and
`scripts/check_wheel.py` was extended to cover the new data.

## Quality gate results (final run, caches cleared)
Caches were cleared first with `rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov out mcpxw-report`.
Each command was run on its own after the N8 fixes (commit 5cf2688).

| Gate | Result | Evidence |
|---|---|---|
| `uv run ruff check .` | PASS | "All checks passed!" |
| `uv run ruff format --check .` | PASS | "86 files already formatted" |
| `uv run mypy` (strict) | PASS | "Success: no issues found in 43 source files" |
| `uv run pytest --cov=mcp_crosswalk --cov-branch --cov-report=term-missing --cov-fail-under=85` | PASS | 655 passed; total branch coverage 98.93% (v0.1.0: 99.22%) |
| `uv run mcpxw crosswalk validate` | PASS | "Crosswalk valid: 10 risk files, 77 mappings (OWASP catalog 2025-beta)." |
| `uv run mcpxw crosswalk export --format md --out docs/crosswalk.md && git diff --exit-code docs/crosswalk.md` | PASS | wrote file; no diff |
| `uv run pip-audit --cache-dir .cache/pip-audit` | PASS | "No known vulnerabilities found" (only skip: mcp-crosswalk 0.2.0 itself, not on PyPI) |
| `uv build` | PASS | built `dist/mcp_crosswalk-0.2.0.tar.gz` and `dist/mcp_crosswalk-0.2.0-py3-none-any.whl` (the `.cache/uv` warning checked: no `.cache`/`.venv` entries in the sdist) |
| `uv run python -I scripts/check_wheel.py dist/mcp_crosswalk-0.2.0-py3-none-any.whl <empty tmp dir>` | PASS | 76 entries, none missing; data resolved inside the wheel; baselines and 800-171r3 load; validate exit 0; five-format scan; three-output enrich; "WHEEL OK" |

**Demos (final run):**
- `uv run mcpxw scan --config <tmp>/kitchen_sink.json --format json,md,html,sarif,poam --out out/demo` exited 1, the
  expected code for high findings: 11 servers, 22 findings (15 high, 5 medium, 2 low).
- `uv run mcpxw enrich <tmp>/multi_run_extensions.sarif --format sarif,md --out out/enrich-demo` exited 0: 4
  results, 3 enriched, 1 with no MCP ID.
- A read-only check script confirmed all 5 plus 2 expected files exist and that none of the 10 runtime-built fake
  secrets appears in any of them ("DEMO OK").

## Acceptance criteria
| Milestone | Criterion | Met? | Evidence (test name or command) |
|---|---|---|---|
| N0 | Green baseline, PROGRESS_V02.md, commit | Yes | 446 passed after D30/B4; commit e04ec25 |
| N1 | `versions.yaml` with id/file/status/retrieved and default `2025-beta` | Yes | `test_versions.py::test_shipped_versions_file` |
| N1 | Migration model and JSON Schema in `schema/` | Yes | `test_migration_schema_matches_fixture`, `test_schemas.py::test_committed_schemas_are_current` |
| N1 | No real migration shipped; synthetic test-only version and migration | Yes | `test_shipped_migrations_dir_has_no_real_migration`; `tests/fixtures/catalog_versions/` |
| N1 | `--catalog-version` on scan, validate, show, export; unknown exits 2 with the list | Yes | `test_cli_unknown_version_exits_2`, `test_scan_unknown_version_exits_2_before_writing`, `test_show_export_validate_with_test_version`, `test_scan_with_test_version` |
| N1 | `migrate` writes copies (never in place); reports renamed, retired, and new-unmapped; exit 1 on a gap | Yes | `test_migrate_rename_retire_and_new_unmapped`, `test_migrate_never_writes_in_place`, `test_migrate_exit_0_when_no_new_risks`, `test_r6_*`, `test_r7_*` |
| N1 | Migrated files validate against the target fixture catalog | Yes | `test_migrated_files_validate_against_target` |
| N1 | Default behavior unchanged | Yes | `test_explicit_default_version_matches_implicit`, `test_cli_explicit_default_version`; goldens unchanged by N1 |
| N1 | OWASP page fetched once; newer version not adopted | Yes | WebFetch 2026-10-07: still 2025 Phase 3 beta (D31) |
| N2a | MCPXW-011 logic, severity, risk, redaction | Yes | `test_checks.py::test_011_*` (bridge high, other medium, command string, negatives, redaction, bridge name inside URL) |
| N2a | MCPXW-011 cited by every MCP07 mapping that cites MCPXW-007; count stays 77 | Yes | `crosswalk/MCP07.yaml` (IA-9, SC-8(1), SC-23, PR.DS-02); `crosswalk validate`: 77 |
| N2a | Kitchen-sink instance | Yes | `remote-bridge` in `kitchen_sink.json`; `test_kitchen_sink_triggers_every_check` |
| N2b | Both key shapes, JSONC, no-MCP settings, discovery per platform | Yes | `test_vscode_settings.py` (nested, flat, no MCP keys, per-platform discovery) |
| N2b | Other settings never echoed | Yes | `test_discover_scan_never_echoes_other_settings` (all formats and terminal) |
| N2 | Golden diff limited to the milestone's feature | Yes | Inspected: MCP07 coverage lists MCPXW-011, plus the bridge's 002/011 (and 009 with the allowlist) findings and inventory row (D36); N2b changed no existing golden |
| N3 | Five files vendored and recorded in SOURCES.md; in the wheel | Yes | `catalog/frameworks/SOURCES.md` (original two rows byte-identical, D39); wheel check |
| N3 | Known memberships; a control absent from LOW | Yes | `test_ac2_baselines_match_vendored_files`, `test_control_absent_from_low`, `test_membership_equals_independent_read` |
| N3 | IA-5(1) to 03.05.07; exact match only; withdrawn excluded; non-800-53 references ignored | Yes | `test_ia5_1_links_to_password_management`, `test_exact_match_only_no_inheritance`, `test_withdrawn_requirements_excluded_from_vendored_index`, `test_parse_rules_on_synthetic_catalog` |
| N3 | Labeled derived; never counted; no CMMC claim | Yes | `test_derived_links_never_count_toward_totals`, `test_docs_have_derived_columns_and_labels`, `test_repo_hygiene.py::test_no_cmmc_alignment_claims` |
| N3 | Docs columns, `show`, report JSON (additive, schema updated), Markdown/HTML baselines | Yes | `test_csv_rows_carry_derived_values`, `test_show_prints_derived_context`, `test_report_controls_have_additive_fields`; committed docs match a fresh export |
| N4 | `poam` format and columns in order; one row per finding; sort order | Yes | `test_poam.py::test_columns_and_order`, `::test_one_row_per_finding_with_expected_values`, `::test_rows_ordered_by_severity_then_id` |
| N4 | CSV injection neutralized (POA&M and crosswalk CSV) | Yes | `test_poam_neutralizes_hostile_server_names` (`=HYPERLINK(...)` and five other prefixes), `test_crosswalk_csv_export_neutralizes_formulas` |
| N4 | No unredacted secrets; all-formats test includes poam | Yes | `test_hardening.py::test_no_output_format_contains_a_full_secret` (five formats) |
| N4 | Golden normalization handles the date | Yes | `test_golden_poam` (`tests/golden/kitchen_sink.poam.csv`) |
| N4 | No claim of official template conformance | Yes | README: "columns modeled on common POA&M fields" and an explicit non-conformance sentence |
| N5 | Fixture shapes (a) to (g) | Yes | `test_ids_in_rule_id`, `test_ids_only_in_rule_properties_tags`, `test_ids_only_in_message_with_year_suffix`, `test_results_without_ids_are_untouched`, `test_multiple_runs_and_extensions`, `test_bad_input_exits_2_without_traceback`, `test_oversized_input_exits_2`, `test_hostile_strings_preserved_not_executed` |
| N5 | Round-trip preservation; tag dedup; summary counts | Yes | `test_round_trip_preserves_everything_else` (six fixtures), `test_ids_in_rule_id` (dedup), `test_summary_files_and_id_scheme_caution`, `test_r10_not_enriched_breakdown` |
| N5 | Exit codes 0 and 2; offline; no URI fetching | Yes | `test_bad_input_*`, `test_unknown_format_and_version_exit_2`, `test_offline_and_never_fetches_or_reads_uris` |
| N5 | Enriched SARIF validates against the official schema | Yes | `test_enriched_sarif_validates_against_official_schema` |
| N5 | ID-scheme caution in summary and README | Yes | `test_summary_files_and_id_scheme_caution`; README "ID numbering caution" |
| N6 | Version 0.2.0; CHANGELOG | Yes | `test_cli_version.py`; `CHANGELOG.md` [0.2.0] |
| N6 | README repositioned with Related work; no "first/only"; URLs not fetched | Yes | README; `test_readme_makes_no_first_or_only_claims`; D46 |
| N6 | Methodology and threat-model additions | Yes | `docs/methodology.md` (derived data, versions, enrich IDs); `docs/threat-model.md` T11 to T13, each naming its tests |
| N6 | Regenerated docs and schema; wheel check updated | Yes | `test_committed_markdown_matches_fresh_export`, `test_committed_csv_matches_fresh_export`, `test_committed_checks_doc_is_current`, `test_committed_schemas_are_current`; WHEEL OK |
| N7 | Cache clear, full gate, demos | Yes | Gate table and demos above (run twice: after N6 and after N8) |
| N8 | Independent review; fixes; re-run; report | Yes | Below; D47 |

## Crosswalk and derived data
- Authored mappings: **77** (unchanged; 54 SP 800-53 and 23 CSF 2.0; all `review_status: draft`).
- Checks: **11** (MCPXW-001 to MCPXW-011).
- Distinct SP 800-53 controls in the crosswalk: 40. Baseline membership: **LOW 17, MODERATE 31, HIGH 33,
  PRIVACY 2, none 7**.
- Derived 800-171r3 links: **21** requirements across **23** mapped 800-53 controls (exact ID match; withdrawn
  excluded). The independent reviewer reproduced all of these numbers with its own parser.

## Independent review
A fresh read-only general-purpose subagent reviewed N1 to N6, the BUILD_SPEC §3 principles for every new feature,
and the CLAUDE.md §2 safety rules. It ran probes only under the session scratchpad and confirmed `git status` stayed
clean. It found no network, subprocess, or out-of-`--out` writes in `src/`, and no CMMC claim. Derived links were
correctly labeled and excluded from totals. **Spot checks:** 10 of 10 baseline memberships PASS (AC-17, AC-21, AC-3,
AC-4, AC-4(8), AC-6(1), AU-10, IA-5(7), SA-9, SC-28) and 10 of 10 derived links PASS (CM-7, CM-7(5), CM-8, IA-2,
IA-5, RA-5, SA-9, SC-23, SC-28, SC-8(1)).

Findings (details and tests in DECISIONS D47):

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| R1 | medium | `enrich` wrote `1e400` back as the non-JSON `Infinity` | Fixed: non-finite numbers rejected (exit 2); `allow_nan=False` |
| R2 | medium | Any `settings.json` was parsed as VS Code settings, hiding another client's `mcpServers` | Fixed: settings mode only under `.vscode/` or `Code/User/` |
| R3 | medium | URL secrets leaked in four shapes (token as username, fragment, `?k=`, `;token=`) | Fixed in both detection and redaction; added to the all-formats test |
| R4 | medium-low | Rules matched across tool components; `ruleIndex` ignored `toolComponent` | Fixed: lookup only in the owning component |
| R5 | low | Hostnames and paths in message text read as IDs | Fixed: stricter message-text pattern; documented |
| R6 | medium-low | "Never in place" bypassable by letter case on case-insensitive file systems | Fixed: file-identity comparison |
| R7 | low | Only two crosswalk directories protected | Fixed: every configured crosswalk directory and `catalog/` |
| R8 | low | Quadratic rule lookup; unbounded output size | Fixed in part: indexed and cached (linear). Output size not capped; documented as a residual risk |
| R9 | low | Write errors could leave partial or overwritten files | Fixed: shared check-all-then-atomic writer; surrogates exit 2 |
| R10 | low | "Not enriched" count mislabeled | Fixed: three-way breakdown |
| R11 | nit | Forged `mcp-crosswalk` block passed through silently | Fixed: counted and flagged in the summary |
| R12 | nit | CSV prefixes for newline, full-width `＝`, ZWSP, NUL | **Rejected:** the spec and OWASP guidance name exactly six characters; the extras are not evaluated by mainstream spreadsheets and quoting them would alter legitimate values |
| R13 | nit | HIGH baseline version wording; CSV column names; JSON derived note; ".." in POA&M; missing-dir exit code | Fixed, except the CSV column names, which stay snake_case like every other CSV column (the Markdown uses the spec labels) |

## Decisions made without the owner
Most important first (full text in DECISIONS.md):
- **D32:** check risk IDs are translated through the migration for non-default versions. `versions.yaml` gains a
  `crosswalk` field per version, and a version with `crosswalk: null` makes commands exit 2 with a pointer to
  `migrate`.
- **D40 (corrected per R13):** federal data rules. Exact ID match, `rel: reference` links only, the title pattern
  for source controls, and withdrawn requirements excluded. Derived 800-171r3 numbers are shown in Markdown and
  HTML next to the baselines, always labeled.
- **D38:** report `schema_version` 1.0 to 1.1, because the old schema forbids extra properties. The change is
  additive only.
- **D44 / D45 / D43:** `enrich` rejects duplicate keys, NaN, non-finite numbers, and unpaired surrogates, because a
  rewrite would change meaning. Controls include `risk_id`. The default format is `sarif`. The ID regex is
  end-anchored, and message text uses a stricter pattern (R5).
- **D47:** review dispositions, including R3's opaque-value redaction heuristic, R8's uncapped output size, and the
  R12 rejection.
- **D33 / D35 / D34:** migration rules (every old ID listed, no merges), output path safety, and
  `validate --crosswalk-dir`.
- **D36 / D37 (amended by R2):** MCPXW-011 details and kitchen-sink side effects; scope of `settings.json` parsing.
- **D41 / D42:** CSV safety (six prefixes); POA&M shape. POA&M rows are findings only, so the coverage matrix stays
  in the other formats.
- **D39:** the fetch script fetches by ID and keeps the recorded provenance of untouched files.
- **D31:** the OWASP page was re-checked; nothing adopted. **D46:** docs positioning and the CMMC test. **D30:** the
  `CORRECTIONS.md` mount point was added to `.gitignore`.

## Blockers and gaps
- **B4:** the baseline gate failed on the `CORRECTIONS.md` sandbox mount point. Fixed via `.gitignore` (D30).
  `CORRECTIONS.md` was not read or edited.
- **B5:** some compound shell shapes (heredoc plus chained commands, `sed -i`) were refused. The same edits were
  made with the Edit and Write tools, and nothing was retried in disguise.
- **Known gaps (by design, documented):**
  - `enrich` output size is uncapped (R8).
  - Secret detection in URLs and args is still heuristic. A short opaque token can be missed.
  - `enrich` cannot verify that a tool uses official OWASP numbering.
  - Derived federal data inherits any error in NIST's OSCAL files.
  - Branch coverage dipped slightly, from 99.22% to 98.93%.

## Owner actions
- [ ] Review the derived 800-171r3 column and baseline column in docs/crosswalk.md
- [ ] When OWASP publishes the next MCP Top 10, add it to versions.yaml and author the migration file (as of
      2026-10-07 the page still shows the 2025 edition in Phase 3 beta, with no release date; D31). Steps are in
      `catalog/owasp-mcp/migrations/README.md`.
- [ ] Prepare the NIST OLIR submission (separate effort)
- [ ] Items carried over from the v0.1.0 owner checklist that are still open:
  - [ ] Review all 10 crosswalk files and change review_status to reviewed
  - [ ] Confirm the employer IP and outside-activity policy allows publishing
  - [ ] Add author contact details to pyproject.toml and SECURITY.md
  - [ ] Generate an SBOM (Syft) and sign the release (Sigstore), now for v0.2.0
- [ ] Optional: confirm the "Related work" one-line descriptions (taken from V02_SPEC.md, not re-fetched) still
      match each project's current scope before publishing.

## Next steps
Out of scope for v0.2 and not built:
- Active server probing: `tools/list`, tool-description hashing, rug-pull detection. This would make MCP03, MCP06,
  and MCP08 assessable.
- An optional `--max-output-bytes` or streaming mode for `enrich` on very large SARIF.
- An `enrich` option to restrict ID extraction to specific fields, for scanners known to use custom numbering.
- An OSCAL Assessment Results export.
- OLIR-formatted export of the crosswalk.
- AI RMF, EU AI Act, and ISO 42001 mappings, possibly cross-referencing the OWASP MCP Governance mapping.
- A GitHub Action wrapping `scan` and `enrich` with SARIF upload.
- PyPI publishing with signed releases.
- Fleet scanning.
- Deriving CMMC Level 2 context through SP 800-171 **Rev 2**, if NIST publishes an authoritative Rev 2 to Rev 3
  mapping in OSCAL. It would be clearly labeled, and would still not be an alignment claim.
