# Threat model: mcp-crosswalk itself

This document covers threats **to the tool and its users**, not the MCP risks the tool reports on. The tool reads
files that an attacker may control (an MCP config in a cloned repository, or one planted on a machine), and its
reports are read by people and imported into other tools.

## Assets

- The user's machine (code execution, file system).
- Secrets inside the scanned config files.
- The integrity of reports (people and CI make decisions from them).
- The integrity of the tool and its reference data (supply chain).

## Trust boundaries

| Input | Trust | Notes |
|---|---|---|
| MCP config files | **Untrusted** | Server names, commands, args, env, URLs, and headers are attacker-controllable. |
| VS Code `settings.json` | **Untrusted**, mostly irrelevant | Only the `mcp` server keys are read; every other setting is ignored and never echoed. |
| SARIF input to `enrich` | **Untrusted** | Produced by another tool, possibly from attacker-controlled content; may be malformed, huge, or hostile. |
| CLI arguments (`--config`, `--out`, `--allowlist`, `--to`) | Trusted (the operator) | Chosen by the person running the tool. |
| Vendored crosswalk, catalogs, templates | Trusted after review | Shipped in the package; hashes recorded. |
| Report readers (browser, Markdown renderer, SARIF viewer) | Downstream | Must not be able to receive active content. |

## Threats, mitigations, and tests

### T1. Hostile config content executes code

A config names commands such as `npx`, `docker run`, or `bash -c`. Running them would execute attacker code.

- **Mitigation:** the scanner only parses JSON. It never runs, installs, resolves, or connects to anything named in a
  config. The runtime package imports no subprocess, socket, or HTTP modules and makes no `eval`/`exec`/`os.system`
  calls. YAML (allowlist, crosswalk) is loaded with `yaml.safe_load` only.
- **Tests:** `tests/test_hardening.py::test_runtime_package_imports_no_network_or_process_modules`,
  `::test_runtime_package_has_no_dynamic_execution`, `::test_yaml_is_only_loaded_safely`.

### T2. Hostile config content attacks report readers (HTML/Markdown injection)

A server named `<script>alert(1)</script>`, an arg containing `[link](javascript:...)`, or a header value with
`<style>` could execute or restyle content in a viewer.

- **Mitigation:** HTML is rendered with Jinja2 `autoescape=True` and `StrictUndefined`; the page has no JavaScript,
  no external assets, and a restrictive `Content-Security-Policy` meta tag (`default-src 'none'`). Markdown output
  HTML-escapes untrusted values and backslash-escapes Markdown control characters so links and images cannot form.
  JSON and SARIF are produced by `json.dumps`.
- **Tests:** `tests/test_reporters.py::test_html_escapes_hostile_values`, `::test_html_is_self_contained`,
  `::test_markdown_escapes_hostile_values`; golden report `tests/golden/hostile.json`.

### T3. Deceptive names (Unicode bidi / invisible characters)

A server name containing U+202E (right-to-left override) or zero-width characters can display as a different,
trusted-looking name ("Trojan Source").

- **Mitigation:** Markdown and HTML reports replace bidi controls, zero-width characters, and C0/C1 control
  characters with visible `<U+XXXX>` markers. JSON keeps the value, escaped.
- **Tests:** `tests/test_reporters.py::test_bidi_controls_are_neutralized`, `::test_neutralize`;
  `tests/test_repo_hygiene.py` keeps such characters out of this repository's own source.

### T4. Malformed or oversized input crashes or exhausts the tool

- **Mitigation:** every file is read in a guarded block; JSON/JSONC errors, non-UTF-8 bytes, non-object documents,
  excessive nesting, and over-long integer literals become an input record with `status: parse_error` or
  `read_error`, and scanning continues. Files over 50 MB are not parsed. Any unexpected internal error exits 2
  (never 1, the "findings" code) without echoing config content. Unknown keys and odd value types are tolerated.
- **Tests:** `tests/test_parsing.py::test_malformed_file_is_parse_error`, `::test_non_utf8_file_is_read_error`,
  `::test_oversized_file_is_not_parsed`, `::test_non_object_top_level_is_parse_error`,
  `::test_hostile_file_parses_without_crash`; `tests/test_jsonc.py::test_deep_nesting_is_an_error_not_a_crash`.

### T5. Secret leakage through reports or the terminal

Reports are shared, attached to tickets, and uploaded to code-scanning services. A secret copied into a report is a
second leak.

- **Mitigation:** detected secrets are replaced by `[REDACTED len=<n> sha256=<first 8 hex>]` before they reach any
  evidence string. The server inventory redacts **every** env and header value that is not a variable reference.
  In args, the command string, and URLs, one shared classifier (`redact.classify_args`) both drives MCPXW-002 and
  redacts the inventory, so anything flagged is redacted and vice versa: secret-named flags and `NAME=VALUE`
  assignments (including `docker -e`), credential headers, URL passwords, secret query parameters, token-like URL
  path segments, and known token prefixes. Error messages never quote config content, and tracebacks never render
  local variables. Inline shell scripts are summarized by length, never reproduced. The terminal prints only counts and
  paths. Test fixtures contain only placeholders; fake secrets are built at runtime.
- **Tests:** `tests/test_hardening.py::test_no_output_format_contains_a_full_secret` (all five formats, including
  the POA&M CSV, and terminal output), `tests/test_cli_scan.py::test_terminal_output_never_shows_secrets`,
  `tests/test_checks.py::test_011_redacts_url_tokens` (launcher URLs),
  `tests/test_redact.py::test_url_shapes_are_detected_and_redacted` (token as username, `#access_token=`, opaque
  values under any parameter name, `;name=value` path parameters; also in the all-formats test via
  `tests/fixtures/configs/url_shapes.json`),
  `tests/test_vscode_settings.py::test_discover_scan_never_echoes_other_settings` (unrelated settings never echoed),
  `tests/test_redact.py`, `tests/test_checks.py::test_005_does_not_echo_script`,
  `tests/test_repo_hygiene.py::test_no_secret_shaped_strings_in_repo`.
- **Residual risk:** detection outside env/headers is heuristic; a secret in an unusual form (for example a short
  opaque token in a URL path, or a positional argument with no secret-like name) can be missed and would then
  appear in the inventory. The 8-hex-character hash prefix lets someone who already holds a candidate secret confirm it.
  That is intentional (it lets an operator tell which credential leaked) and does not reveal the secret.

### T6. Path traversal or writes outside `--out`

- **Mitigation:** output file names are fixed (`mcpxw-report.{json,md,html,sarif}`, `mcpxw-poam.csv`) and never
  derived from config contents. The writer refuses an existing symlink at a target name (which could redirect the
  write) and refuses an `--out` that is a file. Every target is checked and every text encoded before any file is
  written, and each file is written to a temporary name and moved into place, so a failure cannot leave a
  half-written report. Nothing else is written anywhere.
- **Tests:** `tests/test_hardening.py::test_scan_writes_only_inside_out`,
  `tests/test_reporters.py::test_write_reports_refuses_symlink`, `::test_write_reports_refuses_file_as_dir`.
- **Residual risk:** `--out` itself is chosen by the operator; pointing it at a sensitive directory will overwrite
  files with those five names there.

### T7. Network access at runtime (exfiltration, SSRF, telemetry)

- **Mitigation:** no network code in the runtime package; reference data is vendored, so the tool works fully
  offline.
- **Tests:** `tests/test_hardening.py::test_full_scan_works_with_sockets_disabled` runs discovery, parsing, every
  check, all four reporters, and the crosswalk commands with `socket.socket`, `socket.create_connection`, and
  `socket.getaddrinfo` patched to raise. `tests/test_enrich.py::test_offline_and_never_fetches_or_reads_uris` does
  the same for `enrich` (see T11).

### T8. Discovery reads more than intended

- **Mitigation:** `discover()` takes every root (home, project, platform, `%APPDATA%`) as a parameter and only
  checks the fixed locations in `discovery/locations.py`. It does not walk directories.
- **Tests:** `tests/test_discovery.py::test_discovery_and_parsing_never_touch_real_home` records every `open` and
  `stat` call and asserts all of them are under the test's temporary directory.

### T9. Supply chain of the tool

- **Mitigation:** four runtime dependencies (`typer`, `pydantic`, `pyyaml`, `jinja2`) with lower bounds in
  `pyproject.toml` and exact versions locked in `uv.lock`. `pip-audit` runs in the quality gate. NIST catalogs are
  vendored with SHA-256 recorded in `catalog/frameworks/SOURCES.md`, and every report records the catalog hashes it
  used. The SARIF test schema is vendored with its hash.
- **Tests / gates:** `uv run pip-audit`; `tests/test_catalogs.py::test_sources_md_lists_hashes_of_vendored_files`.
- **Not yet done (owner checklist):** signed releases (Sigstore) and an SBOM for each release.

### T10. Misleading conclusions (integrity of claims)

A reader could treat "no findings" as "compliant", or a finding as a control failure.

- **Mitigation:** every output carries the disclaimer; findings are worded as indicators relevant to controls; risks
  that cannot be assessed statically are listed as "Not assessed (requires active analysis)"; MCP09 is "Not
  assessed" unless an allowlist was supplied; MCPXW-008 is worded as an item to verify. Mappings are marked draft.
- **Tests:** `tests/test_reporters.py::test_every_format_includes_disclaimer`,
  `::test_no_format_makes_compliance_claims`, `::test_every_format_shows_not_assessed_risks`;
  `tests/test_engine.py::test_coverage_without_allowlist`. Derived federal data is labeled and excluded from
  totals, and no output claims CMMC alignment: `tests/test_federal.py::test_derived_links_never_count_toward_totals`,
  `::test_docs_have_derived_columns_and_labels`, `tests/test_repo_hygiene.py::test_no_cmmc_alignment_claims`.

### T11. Untrusted SARIF input to `enrich`

A SARIF file from another tool can be malformed, enormous, deeply nested, or crafted: duplicate keys that change
meaning on rewrite, `file://` or `http://` URIs that a careless tool might open or fetch, and hostile strings
(HTML, formulas, bidi characters) in messages.

- **Mitigation:** 50 MB cap (checked before and while reading); strict JSON parsing that rejects duplicate keys,
  `NaN`/`Infinity`, numbers too large to represent (`1e400`), over-long integers, excessive nesting, non-UTF-8
  bytes, and unpaired surrogate escapes (detected before anything is written), all with exit 2 and a message that
  quotes no content; structural checks for SARIF 2.1.0. The input is only read: no URI in it is resolved, opened, or
  fetched, and nothing is executed. Only `properties["mcp-crosswalk"]` and `nist-...` tags are added; everything else
  is written back as parsed. Hostile strings are kept inside the JSON output (escaped by `json.dumps`) and never
  reach the terminal or the Markdown summary. Output names are fixed, symlinks are refused, and the input file is
  never overwritten.
- **Tests:** `tests/test_enrich.py::test_bad_input_exits_2_without_traceback`, `::test_oversized_input_exits_2`,
  `::test_input_growing_past_cap_while_read`, `::test_offline_and_never_fetches_or_reads_uris` (sockets and
  `urlopen` patched to raise; every `open` recorded),
  `::test_hostile_strings_preserved_not_executed`, `::test_round_trip_preserves_everything_else`,
  `::test_enriched_sarif_validates_against_official_schema`, `::test_output_safety`, `::test_never_overwrites_input`,
  `::test_unexpected_error_exits_2`, `::test_r1_non_finite_numbers_are_rejected`,
  `::test_r9_unpaired_surrogate_writes_nothing`, `::test_r9_second_target_symlink_writes_nothing`,
  `::test_r8_large_input_is_linear`.
- **Residual risk:** output size is not capped. Each enriched result gains a block of controls (a few KB), so a
  50 MB input of many tiny results can produce an output of several GB. Run `enrich` on output from tools you chose
  to run; the input cap bounds the work, not the output.

### T12. CSV and spreadsheet formula injection

Config values become CSV cells in the POA&M export. A server named `=HYPERLINK("http://x","y")` (or starting with
`+`, `-`, `@`, tab, or carriage return) would run as a formula when the CSV is opened in a spreadsheet.

- **Mitigation:** every cell of every CSV the tool writes (`mcpxw-poam.csv`, `crosswalk export --format csv`) goes
  through `csvsafe.safe_cell`, which prefixes a single quote to any cell starting with one of those characters.
  Values are written with RFC 4180 quoting, so commas, quotes, and newlines cannot break the row structure.
- **Tests:** `tests/test_poam.py::test_poam_neutralizes_hostile_server_names`,
  `::test_crosswalk_csv_export_neutralizes_formulas`, `::test_safe_cell_prefixes_formula_starts`,
  `::test_safe_cell_leaves_other_values`.

### T13. Migration writes over the authored crosswalk

`crosswalk migrate` rewrites crosswalk files. Writing in place, or through a planted symlink, would replace reviewed
mappings with unreviewed renumbered copies.

- **Mitigation:** `--out` is refused (exit 2) when it is, or is inside, the source crosswalk directory, any
  version's configured crosswalk directory, or the `catalog/` directory. The check compares resolved paths and file
  identity (`os.path.samefile`) of every existing ancestor, so `..`, symlinked parents, and letter case on
  case-insensitive file systems cannot slip past it. `--out` is also refused when it is a symlink or an existing file;
  and
  for any target `<risk ID>.yaml` that is a symlink or not a regular file. Only `MCPnn.yaml` names from the validated
  catalog are written, and every migrated file is `review_status: draft`.
- **Tests:** `tests/test_versions.py::test_migrate_never_writes_in_place`,
  `::test_migrate_refuses_file_and_symlink_outputs`, `::test_migrate_refuses_symlinked_target_file`,
  `::test_migrate_rename_retire_and_new_unmapped` (source digest unchanged),
  `::test_r6_identity_check_catches_case_variants`,
  `::test_r7_every_configured_crosswalk_and_catalog_are_protected`.

### T14. Reports reveal the local user name

Reports are meant to be shared (tickets, POA&M trackers, code scanning). Config paths, Claude Code project paths,
and paths in server arguments usually start with the home directory, which names the local user.

- **Mitigation:** before rendering, `scan` replaces the home directory with `~` in every string of the report, in
  every format. Matching stops at a path boundary (`/home/alex` does not match inside `/home/alexis`), and Windows
  homes match with either separator in any case. A home of `/` or a bare drive is never replaced. SARIF writes
  home-relative paths as `uri` plus `uriBaseId: HOME`, and still reads line numbers from the real file. `--full-paths`
  turns this off. Usernames that appear elsewhere (for example inside a URL) are not detected.
- **Tests:** `tests/test_homepath.py::test_reports_show_home_as_tilde_by_default` (all formats, SARIF schema),
  `::test_full_paths_flag_keeps_real_paths`, `::test_finding_ids_do_not_depend_on_the_display_setting`,
  `::test_posix_home_replaced_only_at_a_path_boundary`, `::test_root_home_leaves_paths_unchanged`.
