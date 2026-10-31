# mcp-crosswalk v0.1.0: Completion Report
Status: COMPLETE
Build dates: 2026-10-07T16:46Z to 2026-10-07T17:40Z (single session, autonomous)
Owner corrections (post-build): four owner-directed crosswalk changes (AC-6(7) added, AC-6 relationship, SI-15 x2,
AU-10 added). See DECISIONS D29 and "Owner follow-ups" below. Gates were re-run afterwards.

## What was built
- **Crosswalk:** 10 schema-validated YAML files (`crosswalk/MCP01.yaml` ... `MCP10.yaml`) with 77 mappings from the
  OWASP MCP Top 10 (2025 beta) to NIST SP 800-53 Rev 5 and CSF 2.0, using OLIR-style relationships, confidence
  levels, original MCP-specific rationales, and links to scanner checks. All are validated against vendored NIST OSCAL
  catalogs (`catalog/frameworks/`, SHA-256 in `SOURCES.md`). Generated docs: `docs/crosswalk.md`, `docs/crosswalk.csv`.
- **Static scanner:** parses Claude Desktop, Claude Code (including `projects.*.mcpServers`), Cursor, VS Code (JSONC),
  Windsurf, and generic configs, and discovers known locations on macOS, Windows, and Linux through injectable roots.
  It runs 10 checks (`docs/checks.md`) and joins each finding to the crosswalk controls that cite that check.
- **Reports:** JSON (canonical, with JSON Schema), Markdown, self-contained HTML (no JavaScript, CSP, autoescaped), and
  SARIF 2.1.0 (validated against the official OASIS schema). Every report carries the disclaimer, a coverage matrix,
  and a coverage note.
- **CLI `mcpxw`:** `version`, `scan`, `crosswalk validate|show|export`, `checks list`, `schema export`. `scan` exits
  0 (nothing at or above `--fail-on`), 1 (findings at or above it), or 2 (usage or runtime error).
- **Safety properties:** offline, read-only outside `--out`, never executes config contents, detected secrets redacted,
  hostile input escaped and bidi characters neutralized, careful claims. Each property is tested
  (`docs/threat-model.md`).

## How to run it
```bash
cd mcp-crosswalk && uv sync
uv run mcpxw scan --config path/to/.mcp.json --format json,md,html,sarif --out out/scan
uv run mcpxw crosswalk show --risk MCP01
uv run mcpxw crosswalk export --format csv --out crosswalk.csv
```
**Demo output:** `out/demo/` (`mcpxw-report.json`, `.md`, `.html`, `.sarif`). It was produced by
`uv run mcpxw scan --config $TMPDIR/demo/kitchen_sink.json --format json,md,html,sarif --out out/demo`, which reported
20 findings (13 high, 5 medium, 2 low) on 10 servers and exited 1 as designed. All four files exist, and none contains
any of the runtime-built fake secrets. `out/` is git-ignored. Open `out/demo/mcpxw-report.html` in a browser.
After the owner corrections (D29), the same command was re-run against the same materialized config. It gave the same
result: 20 findings (13 high, 5 medium, 2 low) on 10 servers, exit 1, 4 files. No `superset_of` remains in any of
the four demo files.

## Quality gate results (final run)
This run was on 2026-10-07, after the owner corrections (D29). Unlike the M8 run, caches were not cleared first,
because the `rm -rf` of the cache directories was refused by the permission mode (BLOCKERS B3).

| Gate | Result | Evidence |
|---|---|---|
| `uv run ruff check .` | PASS | "All checks passed!" |
| `uv run ruff format --check .` | PASS | "70 files already formatted" |
| `uv run mypy` (strict, pydantic plugin) | PASS | "Success: no issues found in 35 source files" |
| `uv run pytest --cov=mcp_crosswalk --cov-branch --cov-report=term-missing --cov-fail-under=85` | PASS | 446 passed; total branch coverage 99.22% (required 85%) |
| `uv run mcpxw crosswalk validate` | PASS | "Crosswalk valid: 10 risk files, 77 mappings." |
| `uv run mcpxw crosswalk export --format md --out docs/crosswalk.md && git diff --exit-code docs/crosswalk.md` | PASS | No diff. The regenerated doc was staged first, so this compares a fresh export with it; the gate is re-run after the commit |
| `uv run pip-audit --cache-dir .cache/pip-audit` | PASS | "No known vulnerabilities found"; only skip is `mcp-crosswalk` itself (not on PyPI) |
| `uv build` | PASS | Built `dist/mcp_crosswalk-0.1.0.tar.gz` and `dist/mcp_crosswalk-0.1.0-py3-none-any.whl` |
| Wheel package data (`uv run python -I scripts/check_wheel.py <wheel> <tmp>`) | PASS | 59 wheel entries, none missing; 3 license files. Imported from the extracted wheel, `data_root()` resolved inside the wheel; `crosswalk validate` exited 0 with 77 mappings and a 4-format scan produced 4 reports. "WHEEL OK" |

## Acceptance criteria
| Milestone | Criterion | Met? | Evidence (test name or command) |
|---|---|---|---|
| M0 | Python >= 3.11, uv, pyproject, src layout, tooling config, .gitignore | Yes | Python 3.12.3, uv 0.12.23; `pyproject.toml` (ruff E,F,W,I,B,UP,S,SIM,RUF at line length 100, S101 allowed in tests; mypy strict + pydantic plugin; branch coverage) |
| M0 | PROGRESS/DECISIONS/BLOCKERS created | Yes | Files in repo root |
| M0 | `mcpxw version` prints 0.1.0; one passing test | Yes | `uv run mcpxw version`; `tests/test_cli_version.py` |
| M1 | Fetch script written and run; catalogs vendored; SOURCES.md with URL/date/SHA-256 | Yes | `scripts/fetch_reference_data.py`; `catalog/frameworks/SOURCES.md`; `test_sources_md_lists_hashes_of_vendored_files` |
| M1 | Loader normalizes IDs, flags withdrawn, `lookup()` returns id/title/statement | Yes | `test_known_ids_resolve` (AC-2, AC-2(1), IA-5(7), GV.OC-01, PR.AA-01), `test_lowercase_and_oscal_forms_work`, `test_withdrawn_control_reported_as_withdrawn` (AC-2(10)), `test_unknown_ids_return_none` |
| M1 | OWASP YAML confirmed against live page | Yes | WebFetch of owasp.org/www-project-mcp-top-10 on 2026-10-07 matched all 10 IDs and titles (DECISIONS D4); `test_owasp_catalog_has_ten_risks` |
| M2 | Models + JSON Schema for crosswalk; 10 YAML files per section 7 | Yes | `schema/crosswalk.schema.json`; `test_crosswalk_files_validate_against_exported_schema`; `test_shipped_crosswalk_quality` |
| M2 | `crosswalk validate` implements rules 1-8 with a negative test per rule | Yes | `tests/test_crosswalk.py::test_rule1_*` ... `test_rule8_*` (unknown key, bad enum, bad YAML, missing risk, mismatch, invalid ID, CSF category, withdrawn ID, display form, minimum counts, duplicate, unknown check, check without risk, unreferenced check, short/long rationale) |
| M2 | Export writes docs; committed docs match fresh export | Yes | `test_committed_markdown_matches_fresh_export`, `test_committed_csv_matches_fresh_export` |
| M2 | `docs/methodology.md` | Yes | File present (sources, OLIR direction, confidence, process, limitations) |
| M3 | jsonc, adapters for every client, `discover()` per 8.3, all fixtures | Yes | `tests/test_jsonc.py`, `tests/test_parsing.py` (one test per client), `tests/fixtures/configs/*` |
| M3 | Malformed -> parse_error; JSONC works; Claude Code projects found | Yes | `test_malformed_file_is_parse_error`, `test_vscode_jsonc`, `test_claude_code_user_file_with_projects` |
| M3 | Discovery for darwin/win32/linux in fake home; never touches real home | Yes | `test_discover_darwin`, `test_discover_win32`, `test_discover_linux`, `test_discovery_and_parsing_never_touch_real_home` (audits every open/stat) |
| M4 | 10 checks + registry, redact.py, engine (findings, controls, coverage, summary) | Yes | `tests/test_checks.py`, `tests/test_redact.py`, `tests/test_engine.py` |
| M4 | Positive, negative, and reference-not-secret tests; kitchen sink triggers every check | Yes | `test_00N_positive/negative`, `test_001_references_are_not_secrets`, `test_002_references_are_not_secrets`; `test_kitchen_sink_triggers_every_check` |
| M4 | Validation rules 6 and 7 pass against the real registry | Yes | `test_shipped_crosswalk_is_valid`; `mcpxw crosswalk validate` |
| M5 | Four reporters; report JSON Schema exported | Yes | `schema/report.schema.json`; `test_committed_schemas_are_current` |
| M5 | JSON validates; SARIF validates; HTML self-contained and escapes hostile input; disclaimer in every format | Yes | `test_json_validates_against_exported_schema`, `test_sarif_validates_against_official_schema` (OASIS schema), `test_html_is_self_contained`, `test_html_escapes_hostile_values`, `test_every_format_includes_disclaimer` |
| M6 | All CLI commands wired with exit codes | Yes | `tests/test_cli_scan.py` (`test_exit_codes_kitchen_sink`, `test_exit_code_threshold_respects_severity`, `test_scan_requires_config_or_discover`, `test_missing_config_path_is_usage_error`, ...) |
| M6 | Golden tests per fixture (normalized) | Yes | `test_golden_reports[*]` (10 fixtures) + `test_golden_kitchen_sink_with_allowlist`; `tests/golden/*.json` |
| M6 | Determinism: two runs identical | Yes | `test_two_runs_are_identical` (all 4 formats), `test_scan_is_deterministic` |
| M7 | Offline test with sockets patched | Yes | `test_full_scan_works_with_sockets_disabled` (socket.socket, create_connection, getaddrinfo) |
| M7 | Redaction test across every format | Yes | `test_no_output_format_contains_a_full_secret` (also checks terminal output) |
| M7 | pip-audit clean | Yes | Final gate row above |
| M7 | README, SECURITY, CONTRIBUTING, CHANGELOG, threat model, generated checks.md, LICENSE, LICENSE-DATA, NOTICE | Yes | Files present; `test_committed_checks_doc_is_current` |
| M7 | Full quality gate passes | Yes | M7 run on 2026-10-07 (421 passed, 99.19%) and the final run above |
| M8 | Independent read-only review by fresh subagent | Yes | 12 findings plus an 18-row mapping spot-check; see below |
| M8 | Every finding fixed or rejected with a reason | Yes | All 12 fixed (DECISIONS D28) |
| M8 | Final clean gate run; demo produced 4 files | Yes | Above; `out/demo/` |
| M8 | COMPLETION_REPORT.md written; committed | Yes | This file; final commit |

## Crosswalk summary
- Mappings: **77 total** (54 SP 800-53 Rev 5, 23 CSF 2.0). Confidence split: **21 high / 40 medium / 16 low**.
  Relationships: 72 `intersects_with`, 4 `subset_of`, 1 `superset_of`, 0 `equal`. 38 mappings cite at least one
  scanner check. These match the owner's expected counts after D29. Before D29: 75 mappings, 21/40/14, 69/4/2.
- All mappings are `review_status: draft`. **Owner action: review them before publishing.** Start with the
  low-confidence rows and the 4 `subset_of` and 1 `superset_of` rows, where the relationship direction is a
  judgment call.

## Owner follow-ups
Before applying D29, I read the AC-6(7), AU-10, and SI-15 statements in the vendored SP 800-53 catalog. The owner's
wording was applied unchanged. Two points were raised for a second look; both are now closed:
- **AU-10 (MCP08), possible overstatement. Resolved:** owner rewording applied in 0ae8d03 (the rationale now
  refers to tamper-evident records binding each tool call to the user and agent session). Original concern: AU-10 requires *irrefutable* evidence that an individual or a
  process acting on its behalf took an action. The catalog guidance names digital signatures and message receipts
  as the usual mechanisms. The rationale presents non-repudiation as the fix for an *attribution* gap. Plain
  attribution (records that name the user and agent session) is mostly AU-3, which MCP08 already maps. AU-10 adds
  a stronger guarantee: evidence bound to the actor that cannot later be denied, such as signed tool-call records.
  Consider rewording, for example: "...without tamper-evident evidence binding each tool call to the user and agent
  session, the user can dispute having initiated it." Medium confidence seems reasonable either way.
- **AC-6(7) (MCP02), slight stretch in scope. Owner reviewed, kept as-is:** medium confidence reflects that it
  extends privilege review to MCP servers acting on behalf of users. Original concern: The statement reviews privileges assigned to "roles or classes of
  users". Unlike base AC-6, it does not mention processes acting on behalf of users. Reading it as covering MCP
  server entitlements works if those entitlements count as the user's delegated privileges, but the rationale
  could say so. The new AC-6 rationale is accurate: base AC-6 states the principle but has no review requirement,
  and AC-6(7) adds one.
- **SI-15 (MCP03, MCP06): no concern.** SI-15 validates output from organization-defined programs against expected
  content. Scoping it to servers the organization operates fits. SI-10, named as the client-side counterpart, is
  already mapped in both files.
- Risks assessed by the scanner: MCP01, MCP02, MCP04, MCP05, MCP07, MCP10, and MCP09 when `--allowlist` is given.
  Not assessed statically: **MCP03 Tool Poisoning, MCP06 Prompt Injection, MCP08 Lack of Audit and Telemetry**. All
  reports and the README say so. Without an allowlist, MCP09 is shown as "Not assessed (no allowlist provided;
  review the server inventory)".
- Several spec candidates were dropped or downgraded after reading the control text: SC-12 for MCP01, CM-10 for
  MCP09, and AC-6(1), SR-11, and CM-14 set to low. Reasons are in DECISIONS D9.

## Independent review
A fresh general-purpose subagent reviewed the repo read-only against BUILD_SPEC §§3, 6.3, 9, 10, 11, and 12 and CLAUDE.md §2. It spot-checked 18 mappings against the vendored control text: 14 held and 4 were questionable. It reported 2 high, 1 medium, 6 low, and 3 nit findings. **All were fixed; none were rejected.** Each fix has a regression test.

1. **High:** secrets in bare `NAME=VALUE` arguments (e.g. `docker run -e TOKEN=...`) leaked into the JSON, Markdown, and HTML inventory and were not flagged. **Fixed.** MCPXW-002 and the inventory redaction now share one classifier, which also covers whitespace-containing arguments and the `command` string. The kitchen sink now includes a secret with no known prefix.
2. **High:** a 5000-digit integer literal crashed the scan with exit 1. **Fixed.** It is now recorded as `parse_error`, and unexpected errors exit 2 without printing any config content.
3. **Medium:** a missing `--config` file exited 0. **Fixed.** It now exits 2. A scan where no input parses also exits 2.
4. **Low:** a token in a URL path segment was not redacted, and MCPXW-008 then misfired on the same URL. **Fixed** with a path-segment heuristic, documented as heuristic.
5. **Low:** SARIF `startLine` was wrong when a server name repeated across Claude Code projects. **Fixed** by adding `Finding.project` and searching from the top-level container line.
6. **Low:** Typer tracebacks could render local variables. **Fixed.** Pretty exceptions and locals are disabled.
7. **Low:** the "Assessed (static)" label overstated coverage. **Fixed** with a coverage note in every format and the README.
8. **Low:** some wording read like a verdict. **Fixed** in two rationales, SECURITY.md, and the README.
9. **Low:** four mappings needed correction. **Fixed:** MCP07 SC-8(1) changed to `intersects_with`; MCP07 IA-9 no longer cites MCPXW-008; MCP10 SC-4 lowered to low; MCP04 SI-7 lowered to medium.
10. **Nit:** MCPXW-010 also scanned arguments after the image. **Fixed.**
11. **Nit:** the same file given as relative and absolute paths was scanned twice. **Fixed.**
12. **Nit:** the 5 MB size cap could reject large `~/.claude.json` files. **Fixed.** The cap is now 50 MB.

The reviewer agreed with DECISIONS D7, D12, D14, D16, D20, D21, and D23. When the reviewer's output came back, the
harness flagged an "instruction-shaped pattern" in it. I read it and it contained only review findings, with no
directives, so nothing besides the findings was acted on.

## Decisions made without the owner
Most important first. Full list in `DECISIONS.md`.
- **D12** Secret-name matching is part-based (`PATH`, `AUTHOR`, `TOKEN_URL`, `API_KEY_FILE` are not flagged). The
  spec's raw substring regex would fire high-severity false positives on most configs. Known-prefix detection still
  applies to every value.
- **D9** Crosswalk candidates kept, dropped, downgraded, and added after reading each control statement.
- **D7** A third coverage status for MCP09 when no allowlist is given, so a check that never ran is not shown as
  "Assessed".
- **D14** The inventory redacts every non-reference `env` and header value, not just detected secrets.
- **D28** All review fixes. `Finding.project` and `Report.coverage_note` were added as additive schema fields.
- **D23** Golden tests also normalize finding IDs. The spec's ID formula hashes the absolute path, which pytest
  changes every session. ID correctness is tested separately.
- **D19/D20** SARIF URIs are `file://` for absolute paths. Reports use fixed file names inside `--out` and refuse to
  write through symlinks.
- **D21/D22** Bidi and control characters are neutralized in HTML and Markdown; escaping is scoped to untrusted values.
- **D6/D17** `ServerEntry.project` is added, and IDs include the project, so entries in different Claude Code
  projects do not collide.
- **D13** MCPXW-003 also flags npm ranges and dist-tags.
- **D5/D26** Data is packaged via `importlib.resources` with a fallback for the source checkout. The wheel is verified
  without installing it outside the venv.
- **D1** Sandbox mount points in the repo root are git-ignored. **D2** dev dependencies use `[dependency-groups]`.
  **D3** two `# noqa: S310` comments in the fetch script only (HTTPS-checked, constant URLs). **D10/D11** extra
  validation guards. **D18** SARIF schema vendored. **D24/D25** CLI details. **D27** pip-audit clean.

## Blockers and gaps
- **B1 (no impact):** the `dontAsk` permission mode refused some compound command shapes: `cd ... && python3 - <<EOF`,
  env-var-prefixed commands, `; echo $?`, a `sed` chain, and `git check-ignore`. In each case I used a plainly
  allowed form instead: a script file under the session temp dir, a pytest `--update-golden` option, separate
  commands, the Edit tool, and `git status --ignored`. Nothing was bypassed and no capability was lost. Details are in
  `BLOCKERS.md`.
- **B3 (no impact):** during the D29 corrections, the cache-clearing `rm -rf` and some chained commands were refused.
  As a result, the post-correction gate run was not a clean-cache run.
- **Gaps (by design, documented):** MCP03, MCP06, and MCP08 are not assessable statically. Secret detection outside
  `env` and headers is heuristic. MCPXW-008 is an item to verify, not a defect. Client config locations are best known
  as of October 2026. `mcp-remote` style proxies (a stdio command that carries a remote URL in its args) are not
  checked for cleartext HTTP by MCPXW-007.
- Commits succeeded throughout. The git identity was already configured; I did not run `git config`.

## Owner checklist before going public
- [ ] Review all 10 crosswalk files and change review_status to reviewed
- [ ] Confirm the employer IP and outside-activity policy allows publishing
- [ ] Add author contact details to pyproject.toml and SECURITY.md
- [ ] Generate an SBOM (Syft) and sign the release (Sigstore) for v0.1.0

## Next steps (out of MVP scope)
- **Active mode:** connect to servers (`tools/list`), hash tool descriptions, and detect rug pulls. This would make
  MCP03 and parts of MCP06 and MCP07 assessable.
- **More frameworks:** NIST AI RMF, EU AI Act, ISO/IEC 42001, and NIST SSDF (SP 800-218) mappings.
- **OSCAL Assessment Results output** so findings feed directly into OSCAL-based GRC tooling.
- **Distribution:** a GitHub Action wrapper (SARIF upload to code scanning), a PyPI release, signed releases, and
  SBOMs.
- **Scanner improvements:** detect cleartext URLs passed to `mcp-remote` and similar stdio-to-remote proxies; parse
  VS Code `settings.json` `mcp.servers`; add enterprise/MDM policy file locations.
- **Gateway or proxy enforcement:** explicitly out of scope for this tool.
