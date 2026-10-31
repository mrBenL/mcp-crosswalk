# BUILD_SPEC.md: mcp-crosswalk MVP

Owner: Ben Luthy. Builder: Claude Code (autonomous). Read `CLAUDE.md` first; its safety rules override this file.

---

## 1. Purpose and audience

**Problem.** MCP (Model Context Protocol) servers give AI agents tools, and they are being deployed faster than they are governed.
OWASP published an MCP Top 10 (currently beta). Detection tools exist (for example Snyk's mcp-scan), but nothing ties
MCP risks to the control frameworks that GRC teams and auditors already work in.

**Product.** `mcp-crosswalk` (CLI name `mcpxw`) has two parts:
1. **The crosswalk:** versioned, schema-validated YAML that maps each OWASP MCP Top 10 risk to NIST SP 800-53 Rev 5 controls
   and NIST CSF 2.0 subcategories, with NIST OLIR-style relationship types, rationales, and confidence levels.
   This is useful on its own, as published documentation.
2. **The static scanner:** reads MCP client config files, flags risky patterns, and reports findings joined to the crosswalk,
   so a finding says "this is relevant to IA-5(7) and PR.AA-01", not just "secret found".

**Audience.** GRC practitioners, security architects, and auditors first; developers second.
The output must read as credible to a CISSP/CISM-level reviewer: careful wording, traceable sources, honest coverage.

---

## 2. Scope

### In scope (MVP)
- Crosswalk for all 10 OWASP MCP risks to NIST SP 800-53 Rev 5 and NIST CSF 2.0.
- Crosswalk validation against vendored NIST OSCAL catalogs.
- Generated crosswalk documentation (Markdown and CSV).
- Parsing MCP client configs: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, and a generic fallback.
- Discovery of config files in known locations (with an injectable home directory for tests).
- 10 static checks (section 9).
- Reports: JSON (canonical), Markdown, HTML (single self-contained file), SARIF 2.1.0.
- A coverage matrix that states honestly which risks the MVP can and cannot assess statically.
- CLI with CI-friendly exit codes.
- Tests, type checking, linting, docs, licenses.

### Out of scope (list these under "Next steps" in the completion report, do not build them)
- Active mode (connecting to servers, `tools/list`, tool-description hashing, rug-pull detection).
- NIST AI RMF, EU AI Act, ISO 42001, SSDF mappings.
- OSCAL Assessment Results output.
- GitHub Action, PyPI release, signed releases, SBOM generation.
- Any gateway or proxy functionality.

---

## 3. Design principles (each one is testable)

1. **Read-only.** The tool never writes anywhere except the output directory the user names.
2. **Offline.** The tool makes zero network calls at runtime. Test: run a full scan with sockets patched to raise.
3. **Never executes config contents.** It parses JSON only. Nothing named in a config is run.
4. **Secrets never leave redacted form.** A detected secret appears in output only as `[REDACTED len=<n> sha256=<first 8 hex>]`.
   Test: the full fake secret string appears in no output format.
5. **Hostile input is expected.** Config values (server names, args, URLs) are attacker-controllable. HTML output autoescapes everything.
   Test: a server named `<script>alert(1)</script>` renders escaped. Malformed JSON produces a recorded parse error, never a crash.
6. **Careful claims.** Findings are "indicators relevant to" controls. No output ever says "compliant", "non-compliant", "pass", or "fail" about a control.
   Every report carries this disclaimer:
   > Findings are indicators relevant to the listed controls. They are not a compliance determination. Mappings are draft and pending practitioner review.
7. **Honest coverage.** Risks the static scanner cannot assess are shown as "Not assessed (requires active analysis)", never silently omitted.
8. **Deterministic output.** Same input gives the same output (sorted keys and lists, stable finding IDs), except the timestamp.

---

## 4. Tech stack and repo layout

- Python 3.11+ (use the system Python; do not download interpreters).
- Package manager: `uv` (fallback described in `CLAUDE.md` 5.4).
- Runtime deps (keep it to these): `typer`, `pydantic>=2`, `pyyaml`, `jinja2`.
- Dev deps: `pytest`, `pytest-cov`, `ruff`, `mypy`, `types-PyYAML`, `jsonschema`, `pip-audit`.
- Build backend: `hatchling`. Console script: `mcpxw = "mcp_crosswalk.cli:app"`.
- Pin dependency lower bounds in `pyproject.toml`; commit `uv.lock`.

```
<project root>/
├── CLAUDE.md, BUILD_SPEC.md, LAUNCH.md, .claude/settings.json   # instructions: never edit
├── PROGRESS.md, DECISIONS.md, BLOCKERS.md, COMPLETION_REPORT.md   # your working files
├── README.md, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md
├── LICENSE                     # Apache-2.0 (code)
├── LICENSE-DATA.md             # CC BY 4.0 notice for crosswalk/ and catalog/owasp-mcp/ text you wrote
├── NOTICE                      # attribution: OWASP MCP Top 10 (IDs/titles), NIST (public domain)
├── pyproject.toml, uv.lock, .gitignore
├── catalog/
│   ├── owasp-mcp/2025-beta.yaml
│   └── frameworks/
│       ├── SOURCES.md          # URL, retrieval date, SHA-256 for each vendored file
│       ├── nist-800-53r5/NIST_SP-800-53_rev5_catalog.json
│       └── nist-csf-2.0/NIST_CSF_v2.0_catalog.json
├── crosswalk/MCP01.yaml ... MCP10.yaml
├── schema/                     # exported JSON Schemas (crosswalk, report)
├── docs/
│   ├── crosswalk.md            # GENERATED from YAML; do not hand-edit
│   ├── crosswalk.csv           # GENERATED
│   ├── checks.md               # GENERATED from check registry
│   ├── methodology.md          # how mappings were made, OLIR terms, limitations
│   └── threat-model.md         # threats to the tool itself and mitigations
├── src/mcp_crosswalk/
│   ├── __init__.py             # __version__ = "0.1.0"
│   ├── cli.py
│   ├── models.py               # Pydantic models (catalog, crosswalk, server entries, findings, report)
│   ├── catalogs.py             # OSCAL loaders and ID normalization
│   ├── crosswalk.py            # load, validate, export
│   ├── jsonc.py                # comment and trailing-comma tolerant JSON loader
│   ├── redact.py
│   ├── discovery/
│   │   ├── locations.py        # data table of known config paths (section 8.3)
│   │   ├── adapters.py         # per-client parsing into ServerEntry
│   │   └── discover.py
│   ├── checks/
│   │   ├── registry.py
│   │   └── <one module per check>.py
│   ├── engine.py               # run checks, join crosswalk, build coverage, build report
│   └── reporters/
│       ├── json_reporter.py, markdown.py, html.py, sarif.py
│       └── templates/report.html.j2
├── scripts/
│   └── fetch_reference_data.py # downloads OSCAL catalogs, writes SOURCES.md with SHA-256
└── tests/
    ├── fixtures/               # see section 8.4 for naming rules
    ├── golden/                 # expected normalized JSON reports
    └── test_*.py
```

`.gitignore` must include `.venv/`, `.cache/`, `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.coverage`, `htmlcov/`, `dist/`, `out/`.

---

## 5. Reference data

### 5.1 NIST catalogs (public domain), vendored into the repo
| Framework | URL |
|---|---|
| SP 800-53 Rev 5 | `https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json` |
| CSF 2.0 | `https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json` |

- Write `scripts/fetch_reference_data.py` (stdlib `urllib.request` only, timeout 60 s) that downloads both,
  verifies they parse as JSON with a top-level `catalog` key, saves them, and writes `catalog/frameworks/SOURCES.md` with URL, UTC retrieval date, and SHA-256.
- Commit the downloaded files so the tool works offline forever after.
- **Format notes (verified):**
  - 800-53: control IDs are lowercase in OSCAL (`ac-2`, enhancement `ac-2.1`). Normalize for display to `AC-2` and `AC-2(1)`.
    Accept either form as input. Withdrawn controls carry a property such as `status: withdrawn`; detect them and treat them as invalid mapping targets.
  - CSF 2.0: top-level `groups` are functions (`GV`). Categories are `controls` with `class: category` (`GV.OC`), and subcategories are
    controls nested inside them with `class: subcategory` (`GV.OC-01`). Only subcategories are valid mapping targets.
    A subcategory's `title` equals its ID, so take the readable text from the part with `name: statement` (its `prose`).
  - All candidate IDs in section 7 were checked against these two catalog files on 2026-10-07 and exist; withdrawn 800-53 controls carry a `status` prop with value `withdrawn` (for example `ac-2.10`).
- **Fallback if download is blocked:** record in `BLOCKERS.md`; build the loader against a minimal hand-written OSCAL-shaped
  fixture under `tests/fixtures/` so code and tests still work; mark every mapping `catalog_verified: false`;
  report the gap prominently. Do not hand-write a fake "full" catalog.

### 5.2 OWASP MCP Top 10 (CC BY-NC-SA 4.0): IDs and titles only
Source: `https://owasp.org/www-project-mcp-top-10/` (status: Phase 3 beta, as of 2026-10-07). Fetch it once with WebFetch to confirm the list; if it changed, follow the live page and record the change in `DECISIONS.md`.

| ID | Title (official page) | Known alias |
|---|---|---|
| MCP01:2025 | Token Mismanagement & Secret Exposure | |
| MCP02:2025 | Privilege Escalation via Scope Creep | |
| MCP03:2025 | Tool Poisoning | |
| MCP04:2025 | Software Supply Chain Attacks & Dependency Tampering | |
| MCP05:2025 | Command Injection & Execution | |
| MCP06:2025 | Prompt Injection via Contextual Payloads | Intent Flow Subversion |
| MCP07:2025 | Insufficient Authentication & Authorization | |
| MCP08:2025 | Lack of Audit and Telemetry | |
| MCP09:2025 | Shadow MCP Servers | |
| MCP10:2025 | Context Injection & Over-Sharing | |

`catalog/owasp-mcp/2025-beta.yaml` holds, per risk: `id`, `short_id` (`MCP01`), `title`, `aliases`, `summary` (your own words, at most 3 sentences),
`source_url`, plus file-level `version: "2025-beta"`, `retrieved: <date>`, `license_note`.

---

## 6. Data model

Implement as Pydantic v2 models in `models.py`. Export JSON Schemas to `schema/` with a CLI or script command, and test that the exported schemas are current.

### 6.1 Crosswalk file (`crosswalk/MCP0N.yaml`)
```yaml
risk_id: MCP01                    # must exist in the OWASP catalog
catalog_version: 2025-beta
review_status: draft              # draft | reviewed  (always "draft" in this build)
mappings:
  - framework: nist-800-53r5      # nist-800-53r5 | nist-csf-2.0
    control_id: IA-5(7)           # display form; validated against the OSCAL catalog
    relationship: intersects_with # see 6.2
    confidence: high              # high | medium | low
    rationale: >-                 # 1-2 sentences, your own words, specific to MCP
      Plaintext tokens in MCP client config files are embedded static authenticators;
      this enhancement directly addresses keeping them out of configuration and code.
    check_ids: [MCPXW-001, MCPXW-002]   # scanner checks that produce evidence for this mapping; may be empty
```

### 6.2 Relationship vocabulary (NIST OLIR-style, NIST IR 8278)
Direction: the relationship describes **the control's scope relative to the mitigation need for the risk**.
- `equal`: the control and the mitigation need are the same thing.
- `subset_of`: the control covers part of the mitigation need.
- `superset_of`: the control is broader and fully contains the mitigation need.
- `intersects_with`: partial overlap in both directions (expect this to be the most common).
Document this direction precisely in `docs/methodology.md`. Do not use "not related to"; unrelated controls are simply not mapped.

### 6.3 Validation rules (`mcpxw crosswalk validate`, also run in tests)
1. Every file validates against the schema; unknown keys are errors.
2. Exactly one file per OWASP risk; `risk_id` matches the filename.
3. Every `control_id` exists in the vendored catalog for its framework and is not withdrawn.
4. Each risk has at least 3 `nist-800-53r5` mappings and at least 2 `nist-csf-2.0` mappings.
5. No duplicate (framework, control_id) pair within a risk.
6. Every `check_id` refers to a registered check, and that check lists this risk in its `risk_ids`.
7. Every registered check is referenced by at least one mapping.
8. Rationale length is 20 to 400 characters.
Exit 0 when valid; exit 1 with a readable list of every problem otherwise.

---

## 7. Crosswalk authoring requirements

- Write every summary and rationale yourself. Be specific to MCP: name the MCP mechanism (config file, tool description, stdio command, remote transport) in the rationale.
- Prefer precise control enhancements over base controls when an enhancement fits better (for example `IA-5(7)`, `CM-7(5)`, `AC-6(1)`).
- Use `confidence: low` when a mapping is plausible but indirect. Don't inflate confidence.
- All files get `review_status: draft`. The owner will review them before publishing.

**Candidate starting points.** These are a starting point only. For each one, read the control text in the vendored catalog,
keep it only if it fits, and add better ones you find. The validator is the authority on whether an ID exists.

| Risk | 800-53 Rev 5 candidates | CSF 2.0 candidates |
|---|---|---|
| MCP01 | IA-5, IA-5(7), SC-12, SC-28, AC-3 | PR.AA-01, PR.DS-01 |
| MCP02 | AC-6, AC-6(1), AC-3, CM-7 | PR.AA-05, PR.PS-01 |
| MCP03 | SI-7, SI-10, SR-11, CM-14 | ID.RA-09, PR.DS-10 |
| MCP04 | SR-3, SR-4, SR-11, CM-7(5), RA-5, SI-7 | GV.SC-05, ID.RA-09, ID.AM-02 |
| MCP05 | SI-10, CM-7, AC-6, SC-39 | PR.PS-05, PR.PS-06 |
| MCP06 | SI-10, SI-4, AC-4 | DE.CM-09, PR.DS-10 |
| MCP07 | IA-2, IA-9, AC-17, SC-8, SC-23 | PR.AA-03, PR.DS-02 |
| MCP08 | AU-2, AU-3, AU-6, AU-12, SI-4 | PR.PS-04, DE.CM-09 |
| MCP09 | CM-8, CM-7(5), CM-11, CM-10 | ID.AM-02, PR.PS-05 |
| MCP10 | AC-4, AC-6, SC-4, AC-21 | PR.DS-01, PR.DS-10 |

---

## 8. Config parsing and discovery

### 8.1 Normalized server model (`ServerEntry`)
`name`, `client` (claude_desktop | claude_code | cursor | vscode | windsurf | generic), `source_path`, `scope` (user | project | unknown),
`transport` (stdio | http | sse | unknown), `command`, `args` (list), `env` (dict), `url`, `headers` (dict), `raw_keys` (sorted list of keys seen).

### 8.2 Formats to accept (tolerant: ignore unknown keys, never crash)
- **Top-level containers:** `mcpServers` (Claude Desktop, Claude Code, Cursor, Windsurf, generic) and `servers` (VS Code).
- **Claude Code user file (`~/.claude.json`):** top-level `mcpServers`, plus `projects.<path>.mcpServers` for each project. Parse both.
- **Stdio entries:** `command`, `args`, `env`; optional `type: "stdio"`.
- **Remote entries:** `url` or `serverUrl` (Windsurf); optional `type` of `http`, `streamable-http`, or `sse`; optional `headers`.
  Transport inference: explicit `type` wins; otherwise a URL ending in `/sse` means `sse`; otherwise `http`.
- **VS Code:** files may contain comments and trailing commas. Use `jsonc.py` (string-aware comment stripping). `inputs` entries and `${input:...}` references are not secrets.
- **Malformed files:** record `{path, error}` in the report's `inputs` with `status: "parse_error"` and continue.

### 8.3 Known locations (`discovery/locations.py`, best-known as of this build; keep it a plain data table so it is easy to update)
| Client | Scope | macOS | Windows | Linux |
|---|---|---|---|---|
| Claude Desktop | user | `~/Library/Application Support/Claude/claude_desktop_config.json` | `%APPDATA%/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` |
| Claude Code | user | `~/.claude.json` | same | same |
| Claude Code | project | `<project>/.mcp.json` | same | same |
| Cursor | user | `~/.cursor/mcp.json` | same | same |
| Cursor | project | `<project>/.cursor/mcp.json` | same | same |
| VS Code | user | `~/Library/Application Support/Code/User/mcp.json` | `%APPDATA%/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` |
| VS Code | project | `<project>/.vscode/mcp.json` | same | same |
| Windsurf | user | `~/.codeium/windsurf/mcp_config.json` | same | same |

`discover(home: Path, project_dir: Path, platform: str, appdata: Path | None) -> list[Path]` must take every root as a parameter. No hidden reads of the real environment inside the function; the CLI supplies real values, tests supply `tmp_path` values.

### 8.4 Fixture naming rule (important)
Claude Code protects files named `.mcp.json` and directories named `.vscode` and `.claude` inside the working directory, so you cannot create them in the repo.
Store fixtures under neutral names (for example `tests/fixtures/claude_code_project.json`, `tests/fixtures/vscode_project.jsonc`)
and have tests copy them into `tmp_path` under their real names (`tmp_path/".mcp.json"`, `tmp_path/".vscode"/"mcp.json"`).

**Fake secrets:** never store anything secret-shaped in fixture files. Use placeholders such as `__FAKE_GITHUB_PAT__`,
and have a test helper substitute fake values built at runtime by concatenation (for example `"ghp_" + "X" * 36`).
This keeps the repo free of strings that secret scanners would flag.

Required fixtures (at minimum): one clean config per client; one "kitchen sink" config that triggers every check; a malformed JSON file;
a JSONC file with comments and trailing commas; a hostile config (HTML/script in server names and args); and a Claude Code user file with `projects.*.mcpServers`.

---

## 9. Static checks

Each check is a module that registers: `id`, `title`, `risk_ids`, `severity`, `description`, `remediation` (your own words), and `run(entry) -> list[Finding]`.
`docs/checks.md` is generated from the registry.

| ID | Risks | Severity | Logic |
|---|---|---|---|
| MCPXW-001 | MCP01 | high | Literal secret in `env` values: key name matches `(?i)(token|secret|key|password|passwd|pat|credential|auth)` and the value is non-empty and not a reference; or the value matches a known token prefix (`ghp_`, `gho_`, `github_pat_`, `sk-`, `sk-ant-`, `xoxb-`, `xoxp-`, `AKIA`, `glpat-`, `AIza`). |
| MCPXW-002 | MCP01 | high | Literal secret in `args` (for example `--api-key=...`, `--token ...`, a known prefix), in URL query strings or userinfo, or in `headers` (for example a literal `Authorization: Bearer <value>`). |
| MCPXW-003 | MCP04 | medium | Unpinned package launch: `npx`/`bunx`/`pnpm dlx` with a package that has no `@version` or uses `@latest`; `uvx`/`pipx run` without `==version` or `@version`; `docker run` with an image that has no tag, uses `:latest`, and has no `@sha256:` digest. |
| MCPXW-004 | MCP04 | low | Auto-confirmed install: `npx -y` / `--yes` (installs without a prompt at every launch). |
| MCPXW-005 | MCP05 | high | Shell interpreter as the server command with inline script: command basename in `{bash, sh, zsh, dash, fish, cmd, cmd.exe, powershell, powershell.exe, pwsh}` with `-c`, `/c`, `/k`, `-Command`, or `-EncodedCommand`. |
| MCPXW-006 | MCP02, MCP10 | high | Over-broad filesystem scope: any arg that resolves to a filesystem root or home directory (`/`, `~`, `~/`, `$HOME`, `%USERPROFILE%`, `C:\`, `C:/`, `/Users/<name>`, `/home/<name>`, `C:\Users\<name>`) when the server package or command name contains `filesystem`, or (medium severity) for any other server. |
| MCPXW-007 | MCP07 | high | Remote server over cleartext `http://` to a host other than `localhost`, `127.0.0.1`, or `::1`. |
| MCPXW-008 | MCP07 | low | Remote server with no static auth header configured. Wording must note that OAuth may be negotiated at runtime, so this is an item to verify, not a defect. |
| MCPXW-009 | MCP09 | medium | Server not on the allowlist. Runs only when `--allowlist <file>` is given (YAML list of allowed server names, package names, or URL prefixes). Without an allowlist, it does not run, and the report's inventory section lists every server for manual review. |
| MCPXW-010 | MCP02, MCP05 | high | Container launch with excessive privilege: `docker`/`podman` `run` with `--privileged`, `--pid=host`, `--network=host`, `--cap-add=ALL` or `SYS_ADMIN`, or a volume mount of `/`, the home directory, or the Docker socket. |

**References are not secrets:** `${VAR}`, `${env:VAR}`, `${input:id}`, `$VAR`, `%VAR%`, `{{...}}`, and empty strings.

**Coverage matrix rule:** a risk is "Assessed (static)" if at least one check lists it. MCP03, MCP06, and MCP08 will show
"Not assessed (requires active analysis)" in the MVP. Say this plainly in the README and in every report.

**Finding model:** `id` (first 12 hex characters of SHA-256 over check_id + source_path + server name + evidence key), `check_id`, `title`, `severity`,
`risk_ids`, `server`, `client`, `source_path`, `evidence` (redacted string), `remediation`, `controls` (list of {framework, control_id, title, relationship, confidence} from the crosswalk for the finding's risks, restricted to mappings whose `check_ids` include this check).

---

## 10. Reports

**JSON (canonical).** Top level: `schema_version: "1.0"`, `tool {name, version}`, `generated_at` (UTC ISO 8601), `catalog {owasp_version, frameworks[{id, source_sha256}]}`,
`disclaimer`, `inputs[{path, client, status, servers, error?}]`, `servers[]` (redacted), `findings[]`, `coverage[{risk_id, title, status, check_ids, findings}]`,
`summary {by_severity, total_findings, total_servers}`. Validate output against `schema/report.schema.json` in tests.

**Markdown.** Title, disclaimer, summary table, coverage matrix, findings grouped by severity (each with risk IDs, mapped controls, evidence, remediation), server inventory.

**HTML.** One self-contained file: inline CSS, no JavaScript, no external fonts, scripts, images, or CDNs. Jinja2 with autoescape on.
Visual style: restrained and professional, dark neutral palette with one muted accent, readable at phone width. Sections mirror the Markdown report. Severity is shown as text plus color, never color alone.

**SARIF 2.1.0.** One `rule` per check (with help text and `properties.tags` including the risk IDs and mapped control IDs); one `result` per finding;
`physicalLocation.artifactLocation.uri` = source path; include a `region.startLine` when the server name can be found in the file text, otherwise omit the region.
If the official SARIF 2.1.0 JSON Schema can be fetched from `raw.githubusercontent.com` (oasis-tcs/sarif-spec), vendor it under `tests/schemas/` and validate against it; otherwise use structural tests and record that in `DECISIONS.md`.

---

## 11. CLI (`mcpxw`)

```
mcpxw version
mcpxw scan [--config PATH]... [--discover] [--project-dir PATH] [--allowlist FILE]
           [--format json,md,html,sarif] [--out DIR] [--fail-on high|medium|low|none]
mcpxw crosswalk validate
mcpxw crosswalk show [--risk MCP01] [--framework nist-800-53r5|nist-csf-2.0]
mcpxw crosswalk export --format md|csv|json [--out PATH]
mcpxw checks list
mcpxw schema export [--out DIR]
```
- `scan` requires at least one `--config` or `--discover`; otherwise exit 2 with a helpful message.
- Default formats: `json,md`; default out: `./mcpxw-report/`. Never overwrite files outside `--out`.
- Exit codes: 0 = no findings at or above `--fail-on` (default `high`); 1 = findings at or above threshold; 2 = usage or runtime error.
- Terminal output: a short summary table (counts by severity, assessed vs. not-assessed risks, report paths). Never print unredacted values.

---

## 12. Milestones and acceptance criteria

Work strictly in order. Each milestone ends with the fast gate passing, `PROGRESS.md` updated, and a commit.

**M0: Bootstrap**
- Python >= 3.11 confirmed; uv (or the fallback) working; `pyproject.toml`, src layout, ruff/mypy/pytest config, `.gitignore`.
- `PROGRESS.md`, `DECISIONS.md`, `BLOCKERS.md` created.
- `uv run mcpxw version` prints `0.1.0`. One passing test.
- Tooling config: ruff (line length 100, rules `E,F,W,I,B,UP,S,SIM,RUF`; `S101` allowed in tests); mypy `strict = true` with the pydantic plugin over `src/`; pytest coverage over `src/` with branch coverage.

**M1: Reference data**
- `scripts/fetch_reference_data.py` written and run; both catalogs vendored; `SOURCES.md` has URLs, dates, and SHA-256.
- `catalogs.py` loads both, normalizes IDs, flags withdrawn controls, and exposes `lookup(framework, id)` returning id, title, and statement text.
- Tests: known IDs resolve (`AC-2`, `AC-2(1)`, `IA-5(7)`, `GV.OC-01`, `PR.AA-01`); lowercase input works; a withdrawn 800-53 control is reported as withdrawn; an unknown ID returns none.
- OWASP catalog YAML written and confirmed against the live page (or the deviation recorded).

**M2: Crosswalk**
- Models and JSON Schema for crosswalk files; 10 crosswalk YAML files meeting section 7.
- `mcpxw crosswalk validate` implements every rule in 6.3 and passes. Tests include negative cases for each rule (invalid ID, withdrawn ID, missing risk, duplicate, bad check reference, short rationale).
  Rules 6 and 7 depend on the check registry: implement them now against a registry stub listing the section 9 IDs and risk tags, and finalize them in M4.
- `mcpxw crosswalk export` writes `docs/crosswalk.md` and `docs/crosswalk.csv`; a test confirms the committed docs match a fresh export.
- `docs/methodology.md` written.

**M3: Parsing and discovery**
- `jsonc.py`, adapters for every client in 8.2, `discover()` per 8.3, with all fixtures from 8.4.
- Tests: every fixture parses to the expected `ServerEntry` list; malformed files produce `parse_error`; JSONC works; Claude Code `projects.*` entries are found;
  discovery finds files in a fake home for each platform value (`darwin`, `win32`, `linux`); discovery never touches the real home (test by asserting every path read is under `tmp_path`).

**M4: Checks and engine**
- All 10 checks in section 9 with the registry; `redact.py`; `engine.py` producing findings, joined controls, coverage matrix, and summary.
- Each check has positive tests, negative tests, and reference-not-secret tests where relevant. The kitchen-sink fixture triggers every check at least once.
- The crosswalk validation rules 6 and 7 now pass against the real registry.

**M5: Reporters**
- JSON, Markdown, HTML, and SARIF per section 10, with the report JSON Schema exported to `schema/`.
- Tests: JSON validates against the schema; SARIF validates (or passes structural tests); the HTML has no `<script`, `http://`, or `https://` asset references and escapes the hostile fixture; every format includes the disclaimer.

**M6: CLI and end-to-end**
- All commands in section 11 wired, with exit codes per spec.
- Golden tests: running `mcpxw scan` on each fixture produces JSON that matches `tests/golden/*.json` after normalizing `generated_at`, version, and absolute paths.
- Determinism test: two runs on the same input give identical normalized output.

**M7: Hardening and docs**
- Offline test: a full scan with `socket.socket` and `socket.create_connection` patched to raise still succeeds.
- Redaction test: for every output format, none of the runtime-built fake secrets appears in full.
- `uv run pip-audit --cache-dir .cache/pip-audit` runs clean (or each finding is recorded with its disposition in `DECISIONS.md`).
- Docs: `README.md` (what it is, why, quick start, sample output excerpt, coverage table, limitations, careful-claims disclaimer, attribution, licenses),
  `SECURITY.md` (how to report, scope), `CONTRIBUTING.md`, `CHANGELOG.md` (0.1.0), `docs/threat-model.md` (hostile configs, secret leakage, path traversal via `--out`, supply chain of the tool, and the mitigation and test for each),
  `docs/checks.md` generated, `LICENSE` (Apache-2.0 full text), `LICENSE-DATA.md`, `NOTICE`.
- Full quality gate (section 13) passes.

**M8: Independent review and completion**
1. Launch a fresh subagent (the Task/Agent tool) as an independent reviewer. Give it read-only instructions: review the repo against `BUILD_SPEC.md`
   sections 3, 6.3, 9, 10, 11, and 12; check that safety rules in `CLAUDE.md` section 2 were respected (search for network calls, subprocess use, writes outside `--out`, unredacted secret paths);
   spot-check at least 10 crosswalk mappings by reading the control text in the vendored catalog and judging whether the rationale and relationship hold;
   and return a findings list with severity. It must not edit files.
2. Fix every reviewer finding you agree with. For any you reject, record the reason in `DECISIONS.md`.
3. Run the full quality gate one final time from a clean state (`rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov out mcpxw-report` only; these are build artifacts you created) and capture results.
4. Run a demo: `uv run mcpxw scan --config <kitchen-sink copy in a temp dir> --format json,md,html,sarif --out out/demo` and confirm all four files exist.
   The demo folder is ignored by git; mention its path in the report.
5. Write `COMPLETION_REPORT.md` (section 14). Commit.

---

## 13. Quality gates

**Fast gate (every milestone):**
```
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest -q
```

**Full gate (M7 and the final M8 run), all must pass:**
```
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --cov=mcp_crosswalk --cov-branch --cov-report=term-missing --cov-fail-under=85
uv run mcpxw crosswalk validate
uv run mcpxw crosswalk export --format md --out docs/crosswalk.md && git diff --exit-code docs/crosswalk.md
uv run pip-audit --cache-dir .cache/pip-audit
uv build
```
`uv build` must produce a wheel and sdist in `dist/`; then check that the wheel includes `crosswalk/`, `catalog/`, and the HTML template as package data
(adjust packaging so the installed tool finds its data via `importlib.resources`, not repo-relative paths).

---

## 14. COMPLETION_REPORT.md template

```markdown
# mcp-crosswalk v0.1.0: Completion Report
Status: COMPLETE | PARTIAL
Build dates: <start> to <end>

## What was built
<5-8 lines>

## How to run it
<install + 3 example commands, including the demo output path>

## Quality gate results (final run)
| Gate | Result | Evidence |
|---|---|---|
| ruff check | PASS/FAIL | <summary of output> |
| ... one row per full-gate command ... |

## Acceptance criteria
| Milestone | Criterion | Met? | Evidence (test name or command) |
|---|---|---|---|

## Crosswalk summary
- Mappings: <n> total (<n> 800-53, <n> CSF 2.0); confidence split high/medium/low
- All mappings review_status: draft. **Owner action: review before publishing.**
- Risks assessed by the scanner: <list>. Not assessed statically: <list>.

## Independent review
<reviewer findings, each with fixed / rejected (reason)>

## Decisions made without the owner
<summary of DECISIONS.md, most important first>

## Blockers and gaps
<from BLOCKERS.md; "None" if none>

## Owner checklist before going public
- [ ] Review all 10 crosswalk files and change review_status to reviewed
- [ ] Confirm the employer IP and outside-activity policy allows publishing
- [ ] Add author contact details to pyproject.toml and SECURITY.md
- [ ] Generate an SBOM (Syft) and sign the release (Sigstore) for v0.1.0

## Next steps (out of MVP scope)
<active mode, AI RMF / EU AI Act mappings, OSCAL output, GitHub Action, PyPI>
```
