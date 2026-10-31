# DECISIONS

Decisions made without the owner. Format: decision / options considered / reason.

## D1. Ignore sandbox mount points in `.gitignore`
- **Decision:** add `.bash_profile`, `.bashrc`, `.gitconfig`, `.gitmodules`, `.idea`, `.mcp.json`, `.profile`,
  `.ripgreprc`, `.vscode`, `.zprofile`, `.zshrc` (root-anchored) to `.gitignore`.
- **Options:** leave them untracked (breaks `git add -A`); ignore them.
- **Reason:** the sandbox bind-mounts these as character devices (`/dev/null`) in the project root to protect them.
  They are not project files and git cannot index character devices.

## D2. Dev dependencies via `[dependency-groups]`
- **Decision:** dev tools live in the PEP 735 `dev` dependency group, which `uv run` installs by default.
- **Options:** `[project.optional-dependencies] dev` (needs `--extra dev` on every `uv run`); dependency group.
- **Reason:** keeps the spec's exact gate commands (`uv run pytest`, etc.) working without extra flags.

## D3. Narrow `# noqa: S310` in `scripts/fetch_reference_data.py`
- **Decision:** two `# noqa: S310` comments on the `urllib.request` calls in the fetch script only.
- **Reason:** S310 warns that `urlopen` accepts `file:` and custom schemes. The script checks
  `url.startswith("https://")` immediately before, and the URLs are hard-coded constants. The runtime package
  has no network code at all.

## D4. OWASP catalog confirmed against the live page; alias kept from the spec
- **Decision:** IDs and titles in `catalog/owasp-mcp/2025-beta.yaml` match the live page fetched 2026-10-07
  (Phase 3 beta) exactly. The live index page lists no aliases; the spec's known alias for MCP06
  ("Intent Flow Subversion") is kept in `aliases` because the spec names it.

## D5. Packaged data located with `importlib.resources`, with a source-checkout fallback
- **Decision:** the wheel force-includes `crosswalk/`, `catalog/`, `schema/` as `mcp_crosswalk/data/...`
  (`pyproject.toml`). `resources.data_root()` uses `importlib.resources.files("mcp_crosswalk") / "data"` and
  falls back to the repository root only when that packaged directory is absent (editable dev install).
- **Options:** move the data inside `src/` (breaks the spec's repo layout); symlinks (fragile on Windows);
  the fallback.
- **Reason:** keeps the spec layout and makes the installed wheel self-contained (verified against the built wheel in M7).

## D6. `ServerEntry.project` field
- **Decision:** add an optional `project` field (the `<path>` key) to `ServerEntry` for entries found under
  `projects.<path>.mcpServers` in `~/.claude.json`, and include it in the finding-ID evidence key.
- **Reason:** the same server name can appear under several projects in one file; without the project the
  finding IDs (check + source path + server name + evidence key) would collide.

## D7. Coverage status for MCP09 when no allowlist is given
- **Decision:** coverage rows can have a third status,
  `Not assessed (no allowlist provided; review the server inventory)`, used for a risk whose only checks did not
  run because they need `--allowlist` (MCP09 / MCPXW-009). With an allowlist it is `Assessed (static)`.
- **Reason:** design principle 7 (honest coverage). Showing MCP09 as "Assessed" with zero findings when the
  check never ran would overstate coverage.

## D9. Crosswalk candidate controls kept, dropped, and added (M2)
Each candidate was read in the vendored OSCAL catalog before deciding.
- **Dropped:** `SC-12` for MCP01 (cryptographic key establishment; MCP tokens are bearer authenticators, already
  covered by `IA-5`/`IA-5(7)`); `CM-10` for MCP09 (software usage restrictions are about licensing and copyright, not
  unapproved servers); `SR-11` and `CM-14` were not used as primary MCP03 mappings (kept `CM-14` at `low` only);
  `SC-8` base replaced by the more precise `SC-8(1)` for MCP07.
- **Downgraded:** `AC-6(1)` for MCP02 kept at `low` (the enhancement is about security functions and
  security-relevant information; it applies to home-directory filesystem scope only indirectly). `SR-11` for MCP04
  at `low`. `GV.SC-05` for MCP04 at `low` (most MCP packages have no supplier agreement).
- **Added:** `CM-7(6)` (MCP02, MCP05), `IA-5` base retained alongside `IA-5(7)`, `SI-7(1)`, `SI-15` (MCP03, MCP06),
  `AC-4(8)` (MCP06), `SI-7(15)`, `CM-11` (MCP04), `CM-8(3)`, `SA-9` (MCP09), `PR.IR-01` (MCP05), `PR.AA-05`, `AC-3`
  (MCP07), `AC-17` kept at `low` (MCP07), `PR.AA-05` (MCP10).
- **Reason:** spec section 7 says candidates are a starting point only and confidence must not be inflated.

## D10. Crosswalk control IDs must use display form
- **Decision:** validation also flags a `control_id` written in OSCAL form (`ia-5.7`) and asks for the display form
  (`IA-5(7)`). Lookups accept both forms; only the committed data is held to one form.
- **Reason:** consistent IDs in reports and generated docs.

## D11. `crosswalk_version` consistency check
- **Decision:** validation also flags a `catalog_version` that does not equal the OWASP catalog's `version`.
- **Reason:** cheap guard against mappings drifting from the risk list they were written for.

## D12. Secret-name matching is part-based, not a raw substring regex (MCPXW-001/002)
- **Decision:** names are split into parts (separators and camelCase). A name is secret-like if a part contains
  token/secret/password/passwd/credential, equals pat/auth/authorization/apikey/pwd, or ends in "key"/"keys" —
  unless the *last* part is a locator or setting word (url, uri, path, file, dir, host, port, endpoint, region,
  type, mode, method, enabled, id, name, user, username, header, expiry, expires, ttl). Values that are paths,
  numbers, or booleans are not flagged by name alone. The known-prefix rule always applies regardless of name.
- **Options:** the spec's literal substring regex `(?i)(token|secret|key|password|passwd|pat|credential|auth)`.
- **Reason:** the raw regex flags `PATH`, `PYTHONPATH`, `AUTHOR`, `TOKEN_URL`, and `API_KEY_FILE`, producing
  high-severity false positives on nearly every config and eroding trust with GRC readers. Tested in
  `tests/test_redact.py` and `tests/test_checks.py`. Trade-off: `AWS_ACCESS_KEY_ID` is not flagged by name
  (ends in `id`), but real AWS key IDs are still caught by the `AKIA` prefix rule.

## D13. MCPXW-003 also flags npm version ranges and dist-tags
- **Decision:** besides "no version" and `@latest`, npm specs with a range (`^1.2`, `~1`, `1.x`, `1`, `1.2`) or a
  non-numeric dist-tag (`@next`, `@beta`) are flagged as unpinned. Container images with an explicit non-latest tag
  are treated as pinned, per the spec (tags are mutable; digest pinning is recommended in the remediation text).
- **Reason:** ranges and dist-tags resolve to whatever the registry serves at launch, which is the same
  supply-chain exposure as `@latest`.

## D14. Inventory redaction is conservative
- **Decision:** in `servers[]` (all formats), every `env` and `headers` value that is not a pure reference is replaced
  by the redaction marker, even when it does not look secret (for example `LOG_LEVEL`). Args and URLs are redacted
  selectively (secret flag values, credential headers, URL userinfo passwords, secret query parameters, known
  token prefixes).
- **Reason:** design principle 4. Detection heuristics can miss a secret; blanket redaction of env/header values
  cannot. Env keys stay visible, which is what an inventory reviewer needs.

## D15. `ControlRef.risk_id`
- **Decision:** each control attached to a finding carries the `risk_id` whose mapping supplied it.
- **Reason:** checks with two risks (MCPXW-006: MCP02 + MCP10; MCPXW-010: MCP02 + MCP05) can receive the same
  control (for example `AC-6`) from both risks with different relationship/confidence. Without the risk ID the two
  entries look like duplicates.

## D16. MCPXW-008 does not fire when the URL carries a static credential
- **Decision:** a remote entry with a credential header (literal or reference) or a credential in the URL is
  treated as having static auth configured; only entries with neither are flagged.
- **Reason:** a URL token is static auth (badly placed); MCPXW-002 already reports it at high severity, so a
  second low-severity "no auth" finding would be wrong.

## D17. Finding ID evidence key includes the Claude Code project path
- **Decision:** for entries from `projects.<path>.mcpServers`, the evidence key is `<path>::<key>` and the evidence
  text is prefixed `[project <path>]`. See D6.

## D18. SARIF schema vendored; validated with the official schema
- **Decision:** fetched the OASIS SARIF 2.1.0 JSON Schema from
  `raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json` into
  `tests/schemas/` (provenance and SHA-256 in `tests/schemas/SOURCES.md`). Tests validate SARIF output against it.

## D19. SARIF `artifactLocation.uri` is a file URI for absolute paths
- **Decision:** absolute config paths are emitted as `file:///...` URIs (Windows drive paths too); relative paths
  are percent-encoded relative references.
- **Options:** the raw OS path (invalid as a URI for spaces and Windows backslashes); a file URI.
- **Reason:** SARIF requires a valid URI reference. The finding's plain `source_path` remains in the JSON report.

## D20. Report file names and output safety
- **Decision:** `scan` writes only `mcpxw-report.json`, `.md`, `.html`, `.sarif` directly inside `--out`. It refuses
  to write through an existing symlink at those names, or when `--out` is a file.
- **Reason:** threat model item "path traversal / writes outside --out". Fixed names mean config contents can never
  influence output paths.

## D21. Invisible and bidi characters are neutralized in human-readable reports
- **Decision:** Markdown and HTML render bidi controls, zero-width characters, and C0/C1 control characters from
  config values as visible `<U+XXXX>` markers. JSON and SARIF keep the original values (JSON-escaped).
- **Reason:** a hostile server name could use U+202E to display as something else ("Trojan Source"). A repo hygiene
  test also keeps such characters out of the source tree.

## D22. Markdown escaping scope
- **Decision:** untrusted values (server names, paths, evidence, args, errors) are HTML-entity-escaped and have
  Markdown control characters backslash-escaped; the tool's own text (titles, remediation, control names) only has
  `|` and `~` escaped. Square brackets are not escaped so the redaction marker stays verbatim.

## D23. Golden normalization also replaces finding IDs
- **Decision:** golden comparison normalizes `generated_at`, tool version, absolute temp paths (as the spec says) and
  also finding `id`s.
- **Reason:** the spec's ID formula hashes the absolute `source_path`, and pytest's temp root changes every session,
  so IDs are path-dependent in exactly the way paths are. ID correctness and stability are tested separately
  (`test_finding_ids_match_formula`, `test_two_runs_are_identical`, `test_finding_ids_are_stable_and_distinct`).
  Goldens are regenerated with `uv run pytest tests/test_cli_scan.py --update-golden` (a pytest option, not an env var).

## D24. `checks list --format md` generates `docs/checks.md`
- **Decision:** `mcpxw checks list` takes `--format text|md` and `--out`; `docs/checks.md` is generated with
  `mcpxw checks list --format md --out docs/checks.md`, and a test checks the committed file is current.

## D25. `scan --discover` defaults the project directory to the current directory
- **Decision:** when `--project-dir` is not given, project-scoped locations (`.mcp.json`, `.cursor/mcp.json`,
  `.vscode/mcp.json`) are looked up in the current working directory. All real-environment roots are gathered in
  one function (`cli.discovery_roots`) that tests replace; `discover()` itself never reads the environment.

## D26. Wheel verification without installing outside the project venv
- **Decision:** `scripts/check_wheel.py` extracts the built wheel into an empty temp directory, imports the package
  from there ahead of the editable install, and runs `crosswalk validate` and a four-format `scan`, asserting that
  `importlib.resources` resolved data inside the wheel.
- **Options:** install the wheel into a throwaway venv (would be a `pip install` outside the project venv, which
  CLAUDE.md 2.2 forbids); only list the zip contents (does not prove the lookup works).
- **Reason:** proves the installed layout works while respecting the no-install-outside-venv rule.

## D27. pip-audit result
- **Decision:** none needed. `pip-audit` reported "No known vulnerabilities found". Its only skip is
  `mcp-crosswalk` itself (not on PyPI), which is expected.

## D28. Independent review (M8): dispositions
All 12 reviewer findings were accepted and fixed; none rejected.
1. (high) `NAME=VALUE` args leaked: one shared classifier (`redact.classify_args`) now drives both MCPXW-002 and
   inventory redaction, covering bare/`--env`/`-e` assignments, whitespace-containing args, and the `command`
   string. Test `test_002_flags_exactly_what_inventory_redacts`; kitchen sink gained a no-prefix
   `POSTGRES_PASSWORD=` secret covered by the all-formats redaction test.
2. (high) huge integer literal crashed with exit 1: `jsonc.loads` converts any `ValueError`; adapters record other
   `ValueError`s as `parse_error` with the type name only (messages can quote config content); `scan` has a
   catch-all that exits 2 with no content.
3. (medium) missing `--config` exited 0: now exit 2 before scanning. Also exit 2 when inputs exist but none could
   be parsed (reports are still written). Partial parse errors do not change the exit code.
4. (low) token in URL path: heuristic for long (>= 24), mixed letter+digit, varied (>= 10 distinct chars), non-UUID
   path segments, used by both detection and redaction; documented as a heuristic in README limitations.
5. (low) SARIF line for repeated names: `Finding.project` added; top-level entries search from the least-indented
   `mcpServers`/`servers` key.
6. (low) Typer traceback locals: `pretty_exceptions_enable=False`, `pretty_exceptions_show_locals=False`.
7. (low) "Assessed (static)" overstatement: fixed `coverage_note` added to every format (JSON field, Markdown, HTML,
   SARIF run properties) and the README.
8. (low) verdict-like wording: MCP01 IA-5(7) and MCP02 AC-6 rationales reworded; SECURITY.md "guarantees" ->
   "properties"; README redaction claim made precise.
9. (low) mappings: MCP07 SC-8(1) `subset_of` -> `intersects_with`; MCP07 IA-9 no longer cites MCPXW-008 (rationale
   now about authenticating the server); MCP10 SC-4 medium -> low with "by analogy" rationale; MCP04 SI-7 high ->
   medium with rationale stating pinning is a precondition for verification.
10. (nit) MCPXW-010 now scans only runtime options before the image name.
11. (nit) scan targets deduplicated on the resolved path.
12. (nit) parse size cap raised from 5 MB to 50 MB for large `~/.claude.json` files.
- **Added fields** (`Finding.project`, `Report.coverage_note`) are additive; `schema_version` stays `1.0` because
  this is the first release.
- The harness flagged the reviewer's output as containing an instruction-shaped pattern; on reading it, the output
  contained only findings and no directives, so nothing was acted on beyond the findings above.

## D8. Input status `read_error`
- **Decision:** besides `ok` and `parse_error`, an input can be `read_error` (file missing, unreadable, or not
  UTF-8 decodable). Never a crash.

## D29. Owner crosswalk corrections
- **Decision (post-build, owner-directed):** four crosswalk changes, applied with the owner's rationale wording
  verbatim. `review_status` stays `draft` in every file.
  1. MCP02: added SP 800-53 `AC-6(7)` (`intersects_with`, medium, no check_ids). Placed after `CM-7` so the file
     keeps its high -> medium -> low order within the framework.
  2. MCP02 `AC-6`: relationship `superset_of` -> `intersects_with`; rationale replaced. Confidence (high) and
     check_ids (MCPXW-006, MCPXW-010) unchanged.
  3. MCP03 and MCP06 `SI-15`: confidence medium -> low; rationales replaced and scoped to MCP servers the
     organization operates, with SI-10 as the client-side counterpart. Relationship and check_ids unchanged.
  4. MCP08: added SP 800-53 `AU-10` (`intersects_with`, medium, no check_ids).
- **Reason:** owner-directed.
- **Resulting counts:** 77 mappings (54 SP 800-53, 23 CSF 2.0); 21 high / 40 medium / 16 low; 72 `intersects_with`
  / 4 `subset_of` / 1 `superset_of`. These match the owner's expected numbers exactly.
- **Derived artifacts regenerated:** `docs/crosswalk.md`, `docs/crosswalk.csv`, `docs/checks.md` (its "Mapped
  controls" lists for MCPXW-006 and MCPXW-010 show the AC-6 relationship), and `tests/golden/{hostile,kitchen_sink,
  kitchen_sink_allowlist}.json`. The golden diff is 9 lines, each an AC-6 `relationship` value; nothing else changed.
- **Hard-coded counts in tests:** none. No test asserts mapping totals or confidence counts, so no test number was
  changed.
- **Owner follow-ups:** before applying the edits I read the AC-6(7), AU-10, and SI-15 statements in the vendored
  catalog. Concerns are listed in COMPLETION_REPORT.md under "Owner follow-ups". The wording was applied unchanged.

## D30. Ignore the `CORRECTIONS.md` sandbox mount point (v0.2, N0)
- **Decision:** add root-anchored `/CORRECTIONS.md` to `.gitignore`, as in D1.
- **Reason:** in this run `CORRECTIONS.md` is a character device bind-mounted by the sandbox (it is not tracked by
  git). `ruff format --check .` tried to open it and failed with "Permission denied". Ruff honours `.gitignore`, so
  ignoring the mount point restores the baseline gate without excluding any project file. See BLOCKERS B4.

## D31. OWASP MCP Top 10 page re-checked: no newer version (v0.2, N1)
- **Observed (WebFetch, 2026-10-07):** the page shows the 2025 edition in "Phase 3 (Beta Release and Pilot Testing)",
  marked "We are here right now". IDs and titles MCP01:2025 to MCP10:2025 are unchanged from
  `catalog/owasp-mcp/2025-beta.yaml`. No release date is given; Phase 4 is described as a "Final Release" that will
  incorporate pilot feedback.
- **Decision:** nothing adopted. `2025-beta` stays the only shipped version and the default. Listed as an owner action.

## D32. `versions.yaml` gains a `crosswalk` field; checks are translated, not renumbered (v0.2, N1)
- **Decision:** each version entry has `id`, `file`, `status` (`beta | final | test`), `retrieved`, plus `crosswalk`:
  the directory (relative to the data root) of the crosswalk authored for that version, or `null` if none exists yet.
  Scanner checks keep declaring risk IDs in the default version's numbering; for any other version they are translated
  through the migration from the default (`versions.checks_for`). Findings, coverage, SARIF rule tags, docs, and
  crosswalk rule 6/7 validation all use the translated IDs. Retired IDs drop out of a check's `risk_ids`. With no
  migration file, IDs carry over only if every default ID exists in the target catalog; otherwise it is an error.
  A catalog file's `version` must equal its `versions.yaml` id.
- **Options:** one crosswalk directory per version with checks hard-coded per version; renumber checks in place.
- **Reason:** the spec asks that a new OWASP version can be added "without breaking existing crosswalk files or
  reports". Translation keeps the default behavior byte-identical (golden reports unchanged) and puts all
  version-specific knowledge in data files the owner edits. Commands needing a crosswalk exit 2 with a pointer to
  `crosswalk migrate` when the version has `crosswalk: null`.

## D33. Migration file rules (v0.2, N1)
- **Decision:** every risk ID of `from_version` must appear in `map` (`to: null` to retire), no unknown keys, every
  non-null target must exist in the target catalog, and two old IDs may not map to one new ID. `from_version` and
  `to_version` must match the catalogs. The migration source is always the default version's crosswalk.
- **Reason:** "retired risks are reported, not silently dropped": requiring an explicit entry for every old risk
  makes an omission an error rather than a silent drop. Merges need human judgment about which rationale wins, so the
  tool refuses them instead of guessing.

## D34. `crosswalk validate --crosswalk-dir` (v0.2, N1)
- **Decision:** `crosswalk validate` takes an optional `--crosswalk-dir` to validate a directory other than the
  version's configured crosswalk.
- **Reason:** the migration workflow writes copies to `--out`; without this the owner could not validate them
  against the target catalog before adopting them (the spec's acceptance test "migrated files validate against the
  target fixture catalog"). Small, read-only, and needed by the workflow, so not treated as scope expansion.

## D35. Migration output path safety (v0.2, N1)
- **Decision:** `crosswalk migrate --out` is refused (exit 2) when it resolves to the source crosswalk directory, a
  directory inside it, or the target version's configured crosswalk directory; when it is a symlink or an existing
  file; and per file when a target `<ID>.yaml` is a symlink or not a regular file. Only `<risk ID>.yaml` names (from
  the validated catalog, pattern `MCPnn`) are written.
- **Reason:** "never in place", and the same symlink rule as scan output (D20).

## D36. MCPXW-011 details (v0.2, N2a)
- **Decision:** runs only on entries with a `command`; scans the command string and every arg for `http://` URLs
  (an arg may hold several, for example `--url=http://...`); one finding per URL, keyed by its position. Severity is
  `high` when `mcp-remote`, `supergateway`, or `mcp-proxy` appears in the command or arguments **after URLs are
  removed**, so a host such as `mcp-proxy.example.com` does not raise severity by itself. Evidence shows the URL via
  the existing `redact_url`. Loopback hosts are the same set as MCPXW-007.
- **Kitchen sink:** the new `remote-bridge` server carries `__FAKE_URL_TOKEN__` in its query string, so the
  all-formats redaction test covers launcher URLs. It therefore also yields one MCPXW-002 finding, and one MCPXW-009
  finding in the allowlist golden. Those golden changes are caused by the N2a fixture instance; no other golden line
  changed (MCP07 coverage rows list MCPXW-011 in every golden).
- **Wording:** the evidence verb is "carries", because the careful-claims test bans "pass"/"fail" in every output.

## D37. VS Code `settings.json` parsing scope (v0.2, N2b)
- **Superseded in part by D47 (R2):** only `settings.json` in a VS Code location (`.vscode/` or `Code/User/`) is
  parsed in settings mode; any other `settings.json` is parsed like a normal config.
- **Original decision:** any file named `settings.json` is parsed as VS Code settings: only `"mcp": {"servers": ...}` (nested) and the flat
  `"mcp.servers"` key are read; top-level `mcpServers`/`servers` keys in a settings file are ignored because they would
  belong to some other extension. When both shapes name the same server the nested one wins. Client detection: in
  `.vscode/` -> vscode/project; in `Code/User/` -> vscode/user; elsewhere generic/unknown (still parsed as settings).
- **Reason:** "Other settings keys are ignored and never echoed into reports." A test scans discovered settings
  files in every format and asserts that no unrelated key or marker value appears in any output or in the terminal.

## D38. Report `schema_version` 1.0 -> 1.1 (v0.2, N3)
- **Decision:** bump `schema_version` to `"1.1"` when `ControlRef` gains the optional `baselines` and
  `sp800_171r3_derived` fields (both default to empty lists). No field was removed or changed.
- **Options:** keep `"1.0"`.
- **Reason:** the exported report schema sets `additionalProperties: false`, so a consumer validating against the
  1.0 schema would reject 1.1 reports. A minor version signals "additive" honestly. The only golden changes from N3
  are the two new fields and this line (verified: the golden diff removes no other line).

## D39. Fetch script fetches by ID and preserves recorded provenance (v0.2, N3)
- **Decision:** `scripts/fetch_reference_data.py [ID ...]` fetches only the named files (default: all). Rows for
  files not fetched keep their recorded retrieval date; their SHA-256 is recomputed from disk. N3 ran it with the five
  new IDs only.
- **Reason:** re-downloading the 800-53 and CSF catalogs could silently change the validated control set behind
  the 77 mappings. The two original rows in `SOURCES.md` are byte-identical after the run.

## D40. Derived federal data: parsing rules (v0.2, N3)
- **Baselines:** membership by exact OSCAL ID match against every non-withdrawn control in the resolved-profile
  catalog. Note (corrected after review finding R13): all four vendored baseline files have `metadata.version`
  5.2.0; only the HIGH file's `title` says "Revision 5.1.1". Recorded in `docs/methodology.md`.
- **800-171r3:** requirements are the controls whose ID matches `SP_800_171_NN.NN.NN`; a `status: withdrawn` prop
  excludes one (33 in the vendored file). Only `rel: reference` links count (`addressed_by` and `incorporated_into`
  are ignored). A back-matter resource counts as a source 800-53 control only when its title has the form
  `XX-NN` or `XX-NN(NN)`; everything else (`SP 800-63-3`, the 800-171 publication itself) is ignored. Exact ID match:
  a mapping to `IA-5` does not inherit `03.05.07`, which cites only `IA-05(01)`.
- **Surfaces:** besides the baselines the spec requires next to each 800-53 control in Markdown and HTML, the derived
  800-171r3 numbers are shown there too, always with the "800-171r3 (derived via source 800-53 control)" label.
  `crosswalk show` ends with the CMMC caution line.
- **Counts (N3):** 40 distinct 800-53 controls in the crosswalk; baseline membership LOW 17, MODERATE 31,
  HIGH 33, PRIVACY 2, none 7; 21 distinct 800-171r3 requirements derived across 23 of those controls.

## D41. CSV formula-injection protection (v0.2, N4)
- **Decision:** one helper (`csvsafe.safe_cell`) prefixes a single quote to any cell that starts with `=`, `+`,
  `-`, `@`, tab, or carriage return. It is applied to every cell of the POA&M CSV and of `crosswalk export --format
  csv` (the committed `docs/crosswalk.csv` did not change: no authored cell starts with those characters). A leading
  space is left alone (spreadsheets do not evaluate " =x"). Other characters, including bidi controls, are kept as-is
  in CSV, like JSON (D21 applies to human-rendered Markdown/HTML only).
- **Reason:** spec N4. Tested with `=HYPERLINK("http://x","y")` and the other five prefixes as server names, and
  with a crosswalk rationale that starts with `=`.

## D42. POA&M CSV shape details (v0.2, N4)
- **Decision:** UTF-8 without BOM, header row, RFC 4180 quoting with CRLF line ends. `Weakness Description` is the
  redacted evidence, ". ", then the full report disclaimer. `OWASP MCP Risk` is "<ID> <title>" joined by "; ".
  `Asset` is the server name (a Claude Code project path is already in the evidence). `800-53 Baselines` is
  "<control>: <baselines or none>" per related 800-53 control. Rows are sorted by severity, then finding ID. A scan
  with no findings writes the header only.
- **Coverage:** the POA&M file is one row per finding by design, so it does not carry the coverage matrix. The
  cross-format test "every format shows not-assessed risks" now runs over the four report formats and asserts that
  `poam` is the only format excluded. The coverage statement stays in the JSON/Markdown/HTML/SARIF reports, which
  can be written in the same run. This is a documented scope rule for a findings-only export, not a hidden skip.
- **Golden:** `tests/golden/kitchen_sink.poam.csv` normalizes ID, date, version, and temp path, then sorts rows
  (IDs hash the absolute path, so the true order is asserted in its own test).

## D43. `enrich` ID pattern is end-anchored (v0.2, N5)
- **Decision:** the spec's pattern `\bMCP(0[1-9]|10)(?::20\d\d)?\b` gets its trailing `\b` replaced by
  `(?!\w)(?!:\d)`.
- **Reason:** with the plain `\b`, the regex backtracks out of a malformed suffix, so `MCP07:2025x` and
  `MCP07:1999` were read as MCP07 (found by a test). The anchored form still matches `MCP07`, `mcp07`, `MCP07:2025`,
  `(MCP07)`, `MCP07: title`, and `owasp-mcp-top-10/mcp04`, and still rejects `MCP011`, `XMCP01`, `MCP_01`,
  `MCP01a`, `MCP00`, `MCP11`, and version strings. All cases are in `tests/test_enrich.py::test_find_ids`.

## D44. `enrich` input strictness and round-trip rules (v0.2, N5)
- **Decision:** besides the 50 MB cap (checked by `stat` and again while reading), input is rejected (exit 2) for
  duplicate JSON object keys, `NaN`/`Infinity` constants, integers beyond Python's digit limit, nesting too deep, and
  non-UTF-8 bytes (a UTF-8 BOM is accepted). Structurally it must be an object with `"version": "2.1.0"` and a
  `runs` list of objects whose `results` (if present) are lists of objects. Output is `json.dumps(indent=2,
  ensure_ascii=False)` of the parsed document, so key order and values are preserved; whitespace is not.
- **Reason:** "preserved byte-for-byte in meaning". With duplicate keys, Python keeps the last value, so rewriting
  would silently change meaning; refusing is the honest option. NaN is not JSON.
- **Edge cases:** a result whose `properties` is not an object is counted as not enriched and left untouched; if
  `properties.tags` exists but is not a list, `mcp-crosswalk` is added and the tags are left alone. IDs that match the
  pattern but have no crosswalk file in the selected catalog version are counted in the summary as
  `ids_without_crosswalk` and do not enrich the result.

## D45. `enrich` output details (v0.2, N5)
- **Decision:** each added control has `risk_id` in addition to the spec's `framework, control_id, title,
  relationship, confidence, baselines` (as in D15, two risks can supply the same control with different
  relationship and confidence). Tags are appended in control order, skipping any already present. `--format`
  defaults to `sarif` (summaries are optional, as the spec says); `--out` defaults to `mcpxw-report/`, like `scan`.
  Output names are fixed (`<input stem>.enriched.sarif`, `mcpxw-enrich-summary.json|.md`), written with the scan
  writer's rules (no symlinks, `--out` must be a directory) and never over the input file. `ruleIndex` refers to the
  driver; `rule.index` uses `rule.toolComponent.index` when given; rules are also matched by `ruleId`/`rule.id` in the
  driver and every extension.

## D46. Docs and positioning (v0.2, N6)
- **Related work:** the projects are named and linked with one-line descriptions taken from `V02_SPEC.md`; none of
  the URLs was fetched (the spec lists them for citation only). The README says the descriptions are "as of October
  2026" and points readers to each project for its current scope. The scope sentence uses the spec's wording ("to
  our knowledge as of October 2026, no other public mapping covers ..."); a test bans "the first", "the only", and
  similar claims in the README.
- **CMMC:** a repository test requires every mention of CMMC in the README, `docs/`, and `src/` to sit next to a
  negation, and bans "CMMC aligned/compliant/ready".
- **Stale example fixed:** `docs/methodology.md` used MCP02 `AC-6` as the `superset_of` example, but the owner
  changed that mapping to `intersects_with` (D29). The example is now MCP04 `SR-3`, the only `superset_of` mapping.
- **Version:** `0.2.0` is defined only in `src/mcp_crosswalk/__init__.py` (hatch reads it for the wheel); the version
  test and the wheel-check docstring were updated.
- **Wheel check:** now also requires `versions.yaml`, `migrations/README.md`, the four baseline files, the 800-171r3
  catalog, and the two new schemas, checks that baseline and 800-171r3 lookups resolve inside the extracted wheel,
  and runs a five-format scan and a three-output `enrich` from the wheel.

## D47. Independent review (N8): dispositions
A fresh read-only reviewer reported 13 findings (0 high, 3 medium, 2 medium-low, 4 low, 4 nit) and passed all 20
data spot checks (10 baseline memberships, 10 derived 800-171r3 links; all 40 controls and 21 requirements matched).
Eleven were fixed with regression tests, one was fixed in part, and one was rejected.
1. **R1 (medium) fixed:** `1e400` parsed as infinity and was written back as the non-JSON `Infinity`. A
   `parse_float` hook now rejects non-finite numbers (exit 2), and output uses `allow_nan=False`.
   Tests: `test_r1_non_finite_numbers_are_rejected`, `test_r1_output_is_always_strict_json`.
2. **R2 (medium) fixed:** every `settings.json` was parsed in VS Code settings mode, so another client's
   `settings.json` with a top-level `mcpServers` was silently read as empty. Settings mode now applies only under
   `.vscode/` or `Code/User/`; all discovery locations are inside those. Tests: `test_r2_*`.
3. **R3 (medium) fixed:** `redact_url` missed a token used as the username with no password, fragment parameters,
   opaque values under short parameter names (`?k=`), and `;name=value` path parameters. Detection (`url_secrets`, so
   MCPXW-002) and redaction share one rule set, as in D28: a username of 16 or more characters with no password; the
   fragment parsed like a query; any query, fragment, or path-parameter value that looks opaque (at least 24
   URL-safe characters, at least 8 distinct, not a UUID, path, or URL, and either a mixed letter-digit token, 32 or
   more characters, or all letters) whatever its name; secret-named path parameters. No golden changed. Tests:
   `test_url_shapes_are_detected_and_redacted` and its negative twin; the all-formats test now also scans
   `tests/fixtures/configs/url_shapes.json`.
4. **R4 (medium-low) fixed:** rules were matched by ID across all components, and `ruleIndex` always went to the
   driver. Lookups now use only the owning component (`rule.toolComponent.index`, otherwise the driver), per SARIF
   2.1.0. Tests: `test_r4_*`.
5. **R5 (low) fixed:** in message text, IDs glued to a `.`, `/`, or `-` word (`mcp05.internal.example.com`,
   `servers/mcp01/...`, `mcp-server-mcp03`, `MCP10.2`) are no longer read as risk IDs. Tags and rule fields keep the
   general pattern, because `owasp-mcp-top-10/mcp04` style tags are legitimate. Documented in
   `docs/methodology.md`. Tests: `test_r5_*`.
6. **R6 (medium-low) fixed:** the "never in place" check compared path strings, which misses case variants on
   case-insensitive file systems. It now also compares file identity (`os.path.samefile`) for every existing ancestor
   of `--out`. Test: `test_r6_identity_check_catches_case_variants` (emulates case-insensitivity on Linux).
7. **R7 (low) fixed:** every version's configured crosswalk directory and `catalog/` are now protected, not just
   the source and target. Test: `test_r7_every_configured_crosswalk_and_catalog_are_protected`.
8. **R8 (low) fixed in part:** rule lookup is now indexed per run and component, and controls are cached per
   risk-ID set (20,000 results x 5,000 rules runs well under the 3 s test bound; it took about 4 s before). Output
   size is **not** capped; this is documented as a residual risk in the threat model (T11) and the README.
   A cap would mean writing partial SARIF or refusing valid input, and the input is already capped at 50 MB.
9. **R9 (low) fixed:** a shared writer (`safewrite.write_files`, used by `scan` and `enrich`) checks every target and
   encodes every text before writing anything, then writes each file to a temporary name and renames it into place.
   An unpaired surrogate now exits 2 with a clear message and writes nothing. Tests: `test_r9_*`.
10. **R10 (low) fixed:** "not enriched" is split into no MCP ID, ID without a crosswalk, and `properties` not an
    object, in the JSON and Markdown summaries and on the terminal. Test: `test_r10_not_enriched_breakdown`.
11. **R11 (nit) fixed:** pre-existing `mcp-crosswalk` blocks on results that `enrich` did not enrich are counted and
    called out in the summary. On enriched results they are replaced. Test:
    `test_r11_preexisting_blocks_are_counted_and_flagged`.
12. **R12 (nit) rejected:** prefixing cells that start with a newline, a full-width `＝`, a zero-width space, or NUL.
    The spec and OWASP's CSV-injection guidance name exactly `= + - @`, tab, and carriage return. The reviewer notes
    that no mainstream spreadsheet evaluates the other forms, and quoting more characters would change legitimate
    cell values.
13. **R13 (nit) fixed except one item:** methodology and D40 now say all four baseline files have `metadata.version`
    5.2.0 (only HIGH's title says 5.1.1); POA&M descriptions no longer produce ".." (`.rstrip('.')`);
    `export_json` carries a `derived_fields_note`; `crosswalk validate --crosswalk-dir <missing>` exits 2. **Not
    changed:** the CSV column names `baselines` and `sp800_171r3_derived`. Every other `docs/crosswalk.csv` column
    is a snake_case machine name (`risk_id`, `check_ids`, ...); the spec's human labels "Baselines" and
    "800-171r3 (derived)" are used as the Markdown column headings.
