# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Maintainer review of all 77 crosswalk mappings (2026-10-31). Every risk file is now `review_status: reviewed`.
  Relationships follow the NIST OLIR direction (the OWASP MCP risk relative to the NIST control). Five
  relationship types changed: MCP01 `IA-5(7)`, MCP03 `SI-7(1)`, MCP04 `SI-7(15)`, and MCP06 `AC-4(8)` from
  `subset_of` to `intersects_with`, and MCP04 `SR-3` from `superset_of` to `subset_of`. Confidence for MCP01 `SC-28`
  and `PR.DS-01` lowered to `low`. No mappings added or dropped. The review record is
  `docs/review/crosswalk-review.csv`.
- The report disclaimer now says mappings are maintainer-reviewed and not endorsed by OWASP or NIST.
- Reports show the user's home directory as `~` by default, so shared reports do not reveal the local user
  name. This applies to every format and every string in the report (config paths, project paths, paths in
  server arguments). SARIF writes home-relative paths with `uriBaseId: HOME`. `scan --full-paths` keeps full
  paths. Finding IDs still hash the real path, so they do not change with the setting.

### Security

- Upgraded the dev-only dependencies `filelock` (4.2.6) and `certifi` (2026.10.23) to clear `pip-audit`
  findings. The installed tool does not depend on either.

## [0.2.0] - 2026-10-07

Crosswalk mappings remain draft and pending practitioner review (77 mappings, unchanged in content; four MCP07
mappings now also cite MCPXW-011).

### Added

- `mcpxw enrich INPUT.sarif`: adds crosswalk controls (`properties["mcp-crosswalk"]` and `nist-800-53r5/...`,
  `nist-csf-2.0/...` tags) to SARIF results from other tools that name OWASP MCP risk IDs, with optional JSON and
  Markdown summaries. Untrusted input: 50 MB cap, strict parsing, no URI fetching, exit 2 on bad input.
- Derived federal context for every SP 800-53 control in the crosswalk: LOW, MODERATE, HIGH, and PRIVACY baseline
  membership and SP 800-171 Rev 3 requirements derived via their source 800-53 controls, from newly vendored NIST
  OSCAL files. Shown in `docs/crosswalk.md`/`.csv`, `crosswalk show`, and every report; labeled as derived and
  excluded from mapping totals. No CMMC alignment is claimed.
- `scan --format poam`: `mcpxw-poam.csv`, one row per finding, with columns modeled on common POA&M fields.
- OWASP catalog versioning: `catalog/owasp-mcp/versions.yaml`, a migration file format (`schema/migration.schema.json`),
  `--catalog-version` on `scan`, `enrich`, and `crosswalk validate|show|export`, `crosswalk validate
  --crosswalk-dir`, and `mcpxw crosswalk migrate --to V --out DIR` (never writes in place).
- MCPXW-011: cleartext `http://` remote URL inside a stdio launcher (`mcp-remote`, `supergateway`, `mcp-proxy`).
- VS Code `settings.json` support (`"mcp": {"servers": ...}` and flat `"mcp.servers"`), including discovery of the
  user settings file on macOS, Windows, and Linux and `<project>/.vscode/settings.json`.

### Changed

- Report `schema_version` is now `1.1`: control entries gain the optional `baselines` and `sp800_171r3_derived`
  fields. Nothing was removed.
- README leads with the crosswalk, then `enrich`, then the scanner as a reference implementation, and adds a
  "Related work" section.
- `scripts/fetch_reference_data.py` accepts file IDs so new data can be fetched without re-downloading the rest.

### Security

- Every CSV cell the tool writes (POA&M and crosswalk exports) is protected against spreadsheet formula injection.

## [0.1.0] - 2026-10-07

First release (MVP). Crosswalk mappings are draft and pending practitioner review.

### Added

- Crosswalk from all 10 OWASP MCP Top 10 (2025 beta) risks to NIST SP 800-53 Rev 5 and NIST CSF 2.0: 75 mappings
  with OLIR-style relationship types, confidence levels, MCP-specific rationales, and links to scanner checks.
- Vendored NIST OSCAL catalogs (SP 800-53 Rev 5.2.0, CSF 2.0) with provenance and SHA-256 in
  `catalog/frameworks/SOURCES.md`, and `scripts/fetch_reference_data.py` to refresh them.
- `mcpxw crosswalk validate | show | export` with eight validation rules (schema, one file per risk, IDs exist and
  are not withdrawn, minimum counts, no duplicates, consistent check references, rationale length).
- Generated documentation: `docs/crosswalk.md`, `docs/crosswalk.csv`, `docs/checks.md`; hand-written
  `docs/methodology.md` and `docs/threat-model.md`.
- Config parsing for Claude Desktop, Claude Code (including `projects.*.mcpServers`), Cursor, VS Code (JSONC),
  Windsurf, and generic `mcpServers`/`servers` files; discovery of known locations on macOS, Windows, and Linux.
- Ten static checks (MCPXW-001 to MCPXW-010): literal secrets in env, args, URLs, and headers; unpinned and
  auto-confirmed package launches; shell-wrapped launches; over-broad filesystem scope; cleartext remote transport;
  remote servers without static auth (to verify); allowlist enforcement; privileged container launches.
- Reports in JSON (canonical, with JSON Schema), Markdown, self-contained HTML, and SARIF 2.1.0, each with the
  careful-claims disclaimer and a coverage matrix that lists risks not assessable statically.
- `mcpxw scan` with CI-friendly exit codes (`--fail-on`) and `mcpxw schema export`, `mcpxw checks list`.

### Security

- Offline at runtime, read-only outside `--out`, never executes config contents; secrets redacted as
  `[REDACTED len=<n> sha256=<8 hex>]` in every output; hostile values escaped; bidi control characters neutralized.
