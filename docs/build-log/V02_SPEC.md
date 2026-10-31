# V02_SPEC.md: mcp-crosswalk v0.2.0 (autonomous build)

Owner: Ben Luthy. Builder: Claude Code (autonomous). Start state: v0.1.0 complete, all gates passing, working tree clean.

## 0. How this file relates to the others

- **This file defines WHAT to build in this run.** It supersedes `CLAUDE.md` section 1 (mission) and section 6 (definition of done) for this run only.
- **`CLAUDE.md` sections 2 to 5 apply unchanged:** safety rules, autonomy rules, integrity rules, working method. Re-read them before starting.
- **`BUILD_SPEC.md` is reference material,** not a task list. Its section 3 design principles (read-only, offline, never executes config contents, redaction, hostile input, careful claims, honest coverage, determinism) remain binding on every new feature here.
- **Progress tracking for this run** lives in `PROGRESS_V02.md`, not `PROGRESS.md`. If `PROGRESS_V02.md` exists, you are resuming: read it, `DECISIONS.md`, `BLOCKERS.md`, and `git log --oneline`, then continue from the first unfinished milestone.
- **Never edit:** `CLAUDE.md`, `BUILD_SPEC.md`, `LAUNCH.md`, `V02_SPEC.md`, `CORRECTIONS.md`, or anything in `.claude/`.
- **Record decisions** as new entries in `DECISIONS.md` (continue numbering from the last entry) and blockers in `BLOCKERS.md` (continue numbering).

## 1. Why this release

Research on 2026-10-07 found several open-source MCP config scanners (mcpguard, mcpsec, mcp-audit, agent-audit-kit) that already tag findings with OWASP MCP01 to MCP10, but none maps MCP risks to NIST SP 800-53 Rev 5 or CSF 2.0. The crosswalk is this project's distinct contribution; the scanner is a reference implementation. v0.2.0 therefore:

1. Makes the crosswalk usable by other tools' output (`enrich`).
2. Extends it toward the federal audience (baselines, derived 800-171 Rev 3 links, POA&M export).
3. Prepares for the OWASP MCP Top 10 release scheduled for October 2026 (catalog versions and ID migration).
4. Closes two known scanner gaps.

Do not add rules beyond those listed here. More checks is not the goal.

## 2. Milestones (work strictly in order; each ends with the fast gate passing, PROGRESS_V02.md updated, and a commit)

### N0: Orientation
- Read `CLAUDE.md`, this file, `BUILD_SPEC.md` sections 3 and 6 to 11, `COMPLETION_REPORT.md`, `DECISIONS.md`, `BLOCKERS.md`.
- Run the fast gate (section 4) to confirm a green baseline. If it is not green, record it in `BLOCKERS.md` and fix it first.
- Create `PROGRESS_V02.md`: a 3 to 5 line goal restatement, the N0 to N8 checklist, and a "Current status" line.
- Commit: `N0: v0.2 progress tracking`.

### N1: OWASP catalog versions and ID migration
Goal: when OWASP publishes its next MCP Top 10 (expected October 2026), the project can add it without breaking existing crosswalk files or reports.

- Add `catalog/owasp-mcp/versions.yaml`: a list of available catalog versions (`id`, `file`, `status` such as `beta` or `final`, `retrieved`) and a `default` (stays `2025-beta`).
- Add a migration file format under `catalog/owasp-mcp/migrations/` (for example `2025-beta__to__<next>.yaml`): `from_version`, `to_version`, `map` of old risk ID to new risk ID or `null` (retired), and per-entry `note`. Define it as a Pydantic model and export its JSON Schema to `schema/`.
- Do NOT ship a real migration: the next OWASP version is not published yet. Prove the mechanism with a synthetic test-only version and migration under `tests/fixtures/` (for example a `2099-test` catalog where one risk is renumbered and one is retired).
- Add `--catalog-version` to `scan`, `crosswalk validate`, `crosswalk show`, and `crosswalk export` (default from `versions.yaml`). Unknown versions exit 2 with the list of available versions.
- Add `mcpxw crosswalk migrate --to <version> --out <dir>`: writes migrated copies of the crosswalk files to `<dir>` (never in place), applying the map, and prints a summary of renamed, retired, and new-and-unmapped risks. Retired risks are reported, not silently dropped. Exit 1 if any new risk in the target version has no crosswalk file, so the gap is visible.
- Fetch `https://owasp.org/www-project-mcp-top-10/` once with WebFetch. If a newer version than 2025 beta is published, do NOT adopt it automatically. Record what you saw in `DECISIONS.md` and add it to the completion report's owner actions.
- Tests: version listing, unknown version, migrate rename/retire/new-unmapped cases, migrated files validate against the target fixture catalog, existing behavior unchanged with the default version.

### N2: Scanner gap fixes
**N2a. MCPXW-011: cleartext remote URL inside a stdio launcher.**
- Flags a stdio server whose `command` or `args` contain an `http://` URL whose host is not `localhost`, `127.0.0.1`, or `::1`. This covers stdio-to-remote proxies such as `mcp-remote`, `supergateway`, and `mcp-proxy` that MCPXW-007 misses because the entry has no `url` key.
- Severity: `high` when the command or a package argument contains `mcp-remote`, `supergateway`, or `mcp-proxy`; `medium` otherwise. Risk: MCP07.
- Reuse the existing URL parsing and redaction (tokens in the URL must stay redacted in evidence).
- Crosswalk: add `MCPXW-011` to the `check_ids` of every MCP07 mapping that already cites `MCPXW-007`. Mapping count stays 77.
- Add an instance to the kitchen-sink fixture. Positive, negative (loopback, https), and redaction tests.

**N2b. VS Code `settings.json` MCP servers.**
- Parse MCP servers defined in VS Code `settings.json` under `"mcp": {"servers": {...}}`, and tolerate a flat `"mcp.servers": {...}` key as well. Files are JSONC (reuse `jsonc.py`). Other settings keys are ignored and never echoed into reports.
- Discovery: add user `settings.json` locations (macOS `~/Library/Application Support/Code/User/settings.json`, Windows `%APPDATA%/Code/User/settings.json`, Linux `~/.config/Code/User/settings.json`) and project `<project>/.vscode/settings.json`. Client `vscode`; scope `user` or `project`.
- Remember BUILD_SPEC section 8.4: you cannot create `.vscode/` in the repo. Store fixtures under neutral names and copy them into `tmp_path` in tests.
- Tests: both key shapes, JSONC comments and trailing commas, a settings file with no MCP keys (no servers, no error), discovery per platform under a fake home.

Golden-report rule for N2 (and every later milestone): regenerate goldens with the existing `--update-golden` pytest option, then inspect the diff. Only changes caused by this milestone's feature are allowed. Anything else is a bug to fix, not to accept.

### N3: Federal context: 800-53 baselines and derived 800-171 Rev 3 links
**Reference data.** Extend `scripts/fetch_reference_data.py` to download, verify, and record in `SOURCES.md` (URL, date, SHA-256):

| File | URL |
|---|---|
| LOW baseline | `https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline-resolved-profile_catalog.json` |
| MODERATE baseline | same directory, `NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json` |
| HIGH baseline | same directory, `NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog.json` |
| PRIVACY baseline | same directory, `NIST_SP-800-53_rev5_PRIVACY-baseline-resolved-profile_catalog.json` |
| SP 800-171 Rev 3 | `https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json` |

Vendor them under `catalog/frameworks/` and include them in the wheel. If any download fails, follow the fallback in BUILD_SPEC 5.1 and record a blocker.

**Baselines (verified format notes).** Resolved baseline catalogs list control IDs in OSCAL form (`ac-2`, `ac-2.1`). For each 800-53 control in the crosswalk, compute membership in LOW, MODERATE, HIGH, PRIVACY by exact ID match. This is derived data: never store it in the crosswalk YAML.

**800-171 Rev 3 links (verified format notes).** Each requirement in the 800-171r3 catalog (for example ID `SP_800_171_03.05.07`, title "Password Management") has `links` with `rel: "reference"` pointing (`href: "#<uuid>"`) to back-matter resources whose `title` is a source 800-53 control in zero-padded form, for example `IA-05(01)`. Some resource titles are not 800-53 IDs (for example `SP 800-63-3`); ignore those. 33 requirements carry a `status` prop (withdrawn); exclude withdrawn requirements. Build a reverse index: normalized 800-53 ID to the list of 800-171r3 requirement numbers (display as `03.05.07`) that cite it. Exact ID match only (a crosswalk mapping to `IA-5` does not inherit requirements that cite only `IA-5(1)`); document this rule.

**Labeling rules (careful claims):**
- 800-171r3 links are **derived**, not authored mappings. Label them "800-171r3 (derived via source 800-53 control)". They never count toward mapping totals.
- Do NOT claim CMMC alignment. CMMC Level 2 assessments reference SP 800-171 Rev 2, not Rev 3. Say this in the README and `docs/methodology.md`.

**Surfaces:** `docs/crosswalk.md` and `.csv` gain "Baselines" and "800-171r3 (derived)" columns for 800-53 rows; `crosswalk show` prints them; report JSON control entries gain additive fields `baselines` and `sp800_171r3_derived` (update `schema/report.schema.json`; additive only); Markdown and HTML reports show baselines next to each 800-53 control.

**Tests:** known memberships (for example confirm from the vendored files that `AC-2` is in LOW, MODERATE, and HIGH and assert exactly what the files say), a control absent from LOW, the `IA-5(1)` to `03.05.07` reverse link, withdrawn 800-171 requirements excluded, non-800-53 references ignored, committed docs match a fresh export.

### N4: POA&M export
- Add `poam` to `scan --format`, writing `mcpxw-poam.csv` in `--out`.
- One row per finding. Columns, in order: `POA&M ID` (finding ID), `Weakness Name` (check title), `Weakness Description` (redacted evidence plus the careful-claims disclaimer sentence), `Source` (`mcpxw <version> <check_id>`), `OWASP MCP Risk`, `Asset` (server name), `Client`, `Config File`, `Severity`, `Related 800-53 Controls`, `Related CSF 2.0 Subcategories`, `800-53 Baselines`, `Recommended Remediation`, `Status` (`Open`), `Date Identified` (scan date, YYYY-MM-DD UTC), `Scheduled Completion Date` (blank), `Milestones` (blank), `Comments` (blank).
- Do not claim conformance to the FedRAMP POA&M template or any other official template. The README says "columns modeled on common POA&M fields".
- **CSV injection protection:** config values are attacker-controlled. Any cell whose first character is `=`, `+`, `-`, `@`, tab, or carriage return is prefixed with a single quote. Apply the same protection to `crosswalk export --format csv` if it is not already applied. Test with a hostile fixture value such as `=HYPERLINK("http://x","y")`.
- UTF-8 with a header row, RFC 4180 quoting, deterministic row order (severity, then finding ID).
- Tests: columns and order, one row per finding, CSV injection neutralized, no unredacted secrets (extend the existing all-formats redaction test to include `poam`), golden normalization handles the date.

### N5: `mcpxw enrich`: add controls to other tools' SARIF
Goal: any scanner that tags findings with OWASP MCP IDs can get NIST controls added without switching tools.

```
mcpxw enrich INPUT.sarif [--out DIR] [--format sarif,json,md] [--catalog-version V]
```

- **Input is untrusted.** Size cap 50 MB; malformed JSON or non-SARIF input exits 2 with a clear message and no traceback; never follow or fetch any URI in the file; never execute anything.
- **ID extraction.** For each result, collect OWASP MCP risk IDs from: `ruleId`; the matching rule in `run.tool.driver.rules` and `run.tool.extensions[].rules` (by `ruleIndex` or `id`): its `id`, `name`, `shortDescription.text`, and `properties.tags`; the result's `properties.tags`; and `message.text`. Match `\bMCP(0[1-9]|10)(?::20\d\d)?\b`, case-insensitive, normalized to `MCP01` to `MCP10`. Deduplicate.
- **Enrichment.** For each result with at least one ID, add `properties["mcp-crosswalk"]` = `{catalog_version, risk_ids, controls: [{framework, control_id, title, relationship, confidence, baselines}], disclaimer}`, using ALL crosswalk mappings for those risks (foreign checks are not linked to mcpxw check IDs). Append tags of the form `nist-800-53r5/IA-5(7)` and `nist-csf-2.0/PR.AA-01` to `properties.tags` (create the list if absent; do not duplicate). Change nothing else: every other field in the input is preserved byte-for-byte in meaning (round-trip equality except the added properties and tags).
- **Outputs.** `<input stem>.enriched.sarif` (always, unless `--format` omits `sarif`), plus optional `mcpxw-enrich-summary.json` and `.md`: total results, enriched, not enriched (no MCP ID), counts per risk, catalog version, and the disclaimer.
- **ID-scheme caution.** Some tools use non-official MCP numbering (one known project labels prompt injection as MCP01, while OWASP's MCP01 is Token Mismanagement). The summary and README must state that `enrich` assumes official OWASP MCP Top 10 numbering for the selected catalog version and that users should confirm their scanner uses it.
- **Fixtures:** hand-write synthetic SARIF files covering (a) IDs in `ruleId`, (b) IDs only in rule `properties.tags`, (c) IDs only in `message.text` with a `:2025` suffix, (d) results with no MCP IDs, (e) multiple runs and extensions, (f) malformed and oversized input, (g) hostile strings in messages. Do NOT download, clone, or run any third-party scanner.
- **Tests:** each fixture shape, round-trip preservation, tag dedup, summary counts, exit codes (0 success, 2 bad input), offline and no-URI-fetch (sockets patched), enriched SARIF validates against the vendored official SARIF 2.1.0 schema.

### N6: Docs, positioning, version
- Bump version to `0.2.0` everywhere it is defined. `CHANGELOG.md` entry for 0.2.0.
- **README repositioning:** lead with the crosswalk (the distinct contribution), then `enrich`, then the scanner as a reference implementation. Add a "Related work" section that names and links, neutrally and accurately:
  - OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
  - OWASP MCP Governance & Risk Framework mapping (AI RMF, ISO 42001, SOC 2): https://github.com/OWASP/OWASP-MCP-Governance-and-Risk-Project/blob/main/framework-mapping.md
  - OWASP GenAI Security Project crosswalk (LLM and Agentic lists to many frameworks): https://github.com/GenAI-Security-Project/crosswalk
  - NIST COSAiS (SP 800-53 control overlays for AI): https://csrc.nist.gov/projects/cosais
  - Scanners: agent-audit-kit https://github.com/sattyamjjain/agent-audit-kit, mcpguard https://github.com/loplop-h/mcpguard, mcpsec https://github.com/pfrederiksen/mcpsec, mcp-audit https://github.com/adudley78/mcp-audit, Snyk agent-scan https://github.com/snyk/agent-scan, Cisco mcp-scanner https://github.com/cisco-ai-defense/mcp-scanner
  State this project's scope relative to them in one or two sentences ("to our knowledge as of October 2026, no other public mapping covers the OWASP MCP Top 10 to SP 800-53 Rev 5 and CSF 2.0"). Do not disparage other projects, do not claim to be "the first" or "the only", and do not fetch these URLs (they are listed for citation only).
- `docs/methodology.md`: derived 800-171r3 links, baselines, enrich ID assumptions, catalog versioning.
- `docs/threat-model.md`: add SARIF input as untrusted input, CSV/formula injection, and migration output path safety, each with its mitigation and the test that proves it.
- Regenerate `docs/crosswalk.md`, `docs/crosswalk.csv`, `docs/checks.md`, and `schema/`.
- Update `scripts/check_wheel.py` expectations so the wheel check confirms the new catalogs, migrations schema, and versions file are packaged.

### N7: Full gate and demo
- Clear caches with exactly this command (it is pre-approved): `rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov out mcpxw-report`
- Run the full gate (section 4) and capture results.
- Demos (output under `out/`, which is git-ignored):
  - `uv run mcpxw scan --config <kitchen-sink copy in a temp dir> --format json,md,html,sarif,poam --out out/demo`
  - `uv run mcpxw enrich <one synthetic SARIF fixture copied to a temp dir> --format sarif,md --out out/enrich-demo`
- Confirm every expected file exists and none contains a full fake secret.

### N8: Independent review and completion
1. Launch a fresh read-only reviewer subagent. Scope: this file's N1 to N6 requirements; BUILD_SPEC section 3 principles applied to every new feature; CLAUDE.md section 2 safety rules; specifically: enrich round-trip preservation, ID extraction false positives (for example `MCP011`, `XMCP01`, version strings), CSV injection in every CSV output, derived 800-171r3 links correctly labeled and excluded from totals, no CMMC claims, migration never writes in place, no network or URI fetching in enrich. Spot-check 10 derived 800-171r3 links and 10 baseline memberships against the vendored files. It must not edit files.
2. Fix every finding you agree with; record rejections with reasons in `DECISIONS.md`.
3. Re-run N7 (cache clear, full gate, demos).
4. Write `V02_COMPLETION_REPORT.md` (section 5). Commit.

## 3. Out of scope for v0.2
Active server probing, more static checks beyond MCPXW-011, OLIR submission formatting (the owner will handle NIST OLIR separately), AI RMF / EU AI Act / ISO 42001 mappings, OSCAL Assessment Results, GitHub Action, PyPI publishing, fleet scanning. List any good ideas you have under "Next steps" in the report instead of building them.

## 4. Quality gates
**Fast gate (every milestone):**
```
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest -q
```
**Full gate (N7 and after N8 fixes):** the eight commands from BUILD_SPEC section 13, plus the wheel check `uv run python -I scripts/check_wheel.py <wheel> <tmp dir>`. Coverage must stay at or above 85% branch coverage (it was 99.22%; a large drop is a signal to add tests, not to stop).

**Command shapes:** the permission mode refuses `cd ... &&` chains, heredocs, and environment-variable prefixes (see BLOCKERS B1 to B3). Run commands from the project root as separate, plain commands from the start.

## 5. V02_COMPLETION_REPORT.md template
```markdown
# mcp-crosswalk v0.2.0: Completion Report
Status: COMPLETE | PARTIAL
Build dates: <start> to <end>

## What changed in 0.2.0
<one short paragraph per milestone N1 to N6>

## Quality gate results (final run, caches cleared)
| Gate | Result | Evidence |

## Acceptance criteria
| Milestone | Criterion | Met? | Evidence (test name or command) |

## Crosswalk and derived data
- Authored mappings: <n> (unchanged from 77 unless explained)
- Checks: <n> (11 expected)
- 800-53 controls in crosswalk with baseline membership: LOW <n>, MODERATE <n>, HIGH <n>, PRIVACY <n>, none <n>
- Derived 800-171r3 links: <n> requirements across <n> mapped 800-53 controls

## Independent review
<findings, each fixed or rejected with reason>

## Decisions made without the owner
<new DECISIONS.md entries, most important first>

## Blockers and gaps

## Owner actions
- [ ] Review the derived 800-171r3 column and baseline column in docs/crosswalk.md
- [ ] When OWASP publishes the next MCP Top 10, add it to versions.yaml and author the migration file
- [ ] Prepare the NIST OLIR submission (separate effort)
- [ ] Items carried over from the v0.1.0 owner checklist that are still open

## Next steps
```

## 6. Definition of done for this run
1. N0 to N8 ticked in `PROGRESS_V02.md`.
2. Full gate passes after caches are cleared, with results captured.
3. Independent review done; every finding fixed or rejected with a reason.
4. `V02_COMPLETION_REPORT.md` written and committed; working tree clean.

Final message: start with `V0.2 COMPLETE` or `V0.2 PARTIAL`, then at most 15 lines: what was built, gate results, check and mapping counts, derived-link counts, known gaps, and the report path. Do not claim COMPLETE if any acceptance criterion is unmet.
