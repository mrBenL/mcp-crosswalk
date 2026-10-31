# mcp-crosswalk

[![CI](https://github.com/mrbenl/mcp-crosswalk/actions/workflows/ci.yml/badge.svg)](https://github.com/mrbenl/mcp-crosswalk/actions/workflows/ci.yml)

MCP security scanners report risks by OWASP MCP Top 10 ID, but GRC teams and auditors work in NIST SP 800-53 and
CSF 2.0, and an October 2026 search found no public mapping between them. mcp-crosswalk provides that mapping (77
mappings from the ten OWASP MCP risks to 800-53 Rev 5 controls and CSF 2.0 subcategories) and a CLI, `mcpxw`, that
adds the mapped controls to any scanner's SARIF output.

> Findings are indicators relevant to the listed controls. They are not a compliance determination.
> Mappings are maintainer-reviewed and not endorsed by OWASP or NIST (review record in [`docs/review/`](docs/review/)).

Version 0.2.0. Offline, read-only, Python 3.11+. Not affiliated with OWASP or NIST.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/mrbenl/mcp-crosswalk.git && cd mcp-crosswalk
uv sync

# Look up the controls mapped to a risk
uv run mcpxw crosswalk show --risk MCP01

# Add controls to another scanner's SARIF (here, a sample file from the test fixtures)
uv run mcpxw enrich tests/fixtures/sarif/rule_id.sarif --out out/enrich --format sarif,md

# Scan a sample MCP client config with the reference scanner
uv run mcpxw scan --config tests/fixtures/configs/kitchen_sink.json --out out/scan
```

`scan` exits 1 here because the sample config has high-severity findings. That is expected.

## Sample enriched finding

A SARIF result from another scanner that names `MCP01`, after `mcpxw enrich` (trimmed to three of six controls):

```json
{
  "ruleId": "MCP01",
  "message": { "text": "Token found in config" },
  "properties": {
    "tags": ["security", "nist-800-53r5/IA-5", "nist-800-53r5/IA-5(7)", "nist-800-53r5/SC-28",
             "nist-800-53r5/AC-3", "nist-csf-2.0/PR.AA-01", "nist-csf-2.0/PR.DS-01"],
    "mcp-crosswalk": {
      "catalog_version": "2025-beta",
      "risk_ids": ["MCP01"],
      "controls": [
        { "framework": "nist-800-53r5", "control_id": "IA-5(7)",
          "title": "Authenticator Management | No Embedded Unencrypted Static Authenticators",
          "relationship": "subset_of", "confidence": "high", "baselines": [] },
        { "framework": "nist-800-53r5", "control_id": "IA-5", "title": "Authenticator Management",
          "relationship": "intersects_with", "confidence": "high",
          "baselines": ["LOW", "MODERATE", "HIGH"] },
        { "framework": "nist-csf-2.0", "control_id": "PR.AA-01",
          "title": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
          "relationship": "intersects_with", "confidence": "high", "baselines": [] }
      ],
      "disclaimer": "Findings are indicators relevant to the listed controls. They are not a compliance determination. ..."
    }
  }
}
```

Everything else in the input file is preserved.

## How this differs from MCP scanners

Checked against each project's README on 2026-10-31. See each project for its current scope.

| Project | What it inspects | Tags findings with OWASP MCP IDs | Maps to SP 800-53 / CSF 2.0 |
|---|---|---|---|
| [mcpguard](https://github.com/loplop-h/mcpguard) | Client configs; local stdio servers' tool definitions | Yes | Not in its README |
| [mcpsec](https://github.com/pfrederiksen/mcpsec) | Configs, extension manifests, server source; opt-in remote tool listing | Yes | Not in its README |
| [mcp-audit](https://github.com/adudley78/mcp-audit) | Configs for 10 clients; live tool definitions with `--connect` | Yes | Not in its README |
| [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit) | Configs, code, tool descriptions | Rules cover all ten risks | Maps its rules to 14 frameworks; those named on its pages (EU AI Act, OWASP lists, NSA MCP CSI, Colorado ADMT) do not include 800-53 or CSF 2.0 |
| mcp-crosswalk | Client configs only (reference scanner) | Yes | Yes, per risk |

Their detection is broader than this project's reference scanner, and three of them can inspect live servers,
which `mcpxw scan` never does. This project adds a control layer on top of scanners like these:

- **The unit of mapping is the OWASP risk, not a tool's rule.** Any scanner that emits OWASP MCP IDs gets the
  controls through `mcpxw enrich`, without changing tools.
- **Each mapping states how the control relates to the risk.** Every row has a relationship type (NIST IR 8278
  OLIR style: `subset_of`, `superset_of`, `intersects_with`, `equal`), a confidence level, and a rationale written
  for MCP. A reviewer can see why a control was mapped and how much it covers.
- **Control IDs are checked against NIST's own catalogs.** `mcpxw crosswalk validate` rejects any ID that is not in
  the vendored OSCAL catalogs, or that NIST has withdrawn.
- **Federal context is derived, not guessed.** Each 800-53 control shows the LOW, MODERATE, HIGH, and PRIVACY
  baselines that include it, and the SP 800-171 Rev 3 requirements that cite it, computed from NIST OSCAL files.
  `scan --format poam` writes a POA&M-style CSV.
- **The data is open and versioned.** YAML under CC BY 4.0 with a JSON Schema, and a migration path for when OWASP
  renumbers its list.

## The crosswalk

- Read it: [`docs/crosswalk.md`](docs/crosswalk.md) (also [CSV](docs/crosswalk.csv)). Source:
  [`crosswalk/MCP01.yaml`](crosswalk/MCP01.yaml) to `MCP10.yaml`.
- How it was built: [`docs/methodology.md`](docs/methodology.md).
- 77 mappings: 54 to SP 800-53 Rev 5 (40 distinct controls) and 23 to CSF 2.0.
- **Derived columns are labeled and never counted as mappings.** Baselines and 800-171r3 links come from exact
  control-ID matches in NIST OSCAL files. They do not indicate CMMC alignment: CMMC Level 2 assessments reference
  SP 800-171 Rev 2, not Rev 3.
- **Catalog versions.** The OWASP list is in beta. `catalog/owasp-mcp/versions.yaml` lists catalog versions (default
  `2025-beta`), and `mcpxw crosswalk migrate` writes renumbered copies for a new version from a reviewed migration
  file, without touching the source files (see
  [`catalog/owasp-mcp/migrations/README.md`](catalog/owasp-mcp/migrations/README.md)).

## `mcpxw enrich`

```bash
uv run mcpxw enrich results.sarif --out out/enriched --format sarif,json,md
```

For every result that names a risk ID (`MCP01` to `MCP10`, optionally with `:2025`) in its `ruleId`, its rule's
`id`, `name`, `shortDescription`, or tags, its own tags, or its message text, `enrich` adds
`properties["mcp-crosswalk"]` and `nist-800-53r5/...` and `nist-csf-2.0/...` tags. Output:
`<input stem>.enriched.sarif`, plus optional `mcpxw-enrich-summary.json` and `.md` with counts per risk. The input
is treated as untrusted: capped at 50 MB, parsed strictly, never executed, and no URI in it is fetched or opened.
Exit 0 on success, 2 on unusable input.

**ID numbering caution.** `enrich` assumes the input uses the official OWASP MCP Top 10 numbering for the selected
catalog version (`--catalog-version`, default `2025-beta`). Some tools use their own numbering (one labels prompt
injection `MCP01`, while OWASP's MCP01 is Token Mismanagement & Secret Exposure). Confirm that your scanner uses
the official IDs before relying on the added controls.

## `mcpxw scan`: the reference scanner

Reads MCP client config files (Claude Desktop, Claude Code, Cursor, VS Code `mcp.json` and `settings.json`,
Windsurf, or any `mcpServers`/`servers` JSON), runs eleven static checks, and joins each finding to the crosswalk.

```bash
uv run mcpxw scan --config ~/.cursor/mcp.json --config ./.mcp.json
uv run mcpxw scan --config ./.mcp.json --format json,md,html,sarif,poam --out out/scan
uv run mcpxw scan --discover --project-dir . --allowlist allowlist.yaml --fail-on medium
```

- **Read-only and offline.** It parses JSON. It never starts, installs, or connects to a server named in a config.
- **Redaction.** Detected secrets appear only as `[REDACTED len=<n> sha256=<first 8 hex>]`. Every `env` and header
  value in the server inventory is redacted unless it is a variable reference.
- **Path privacy.** Reports show your home directory as `~`. Use `--full-paths` to keep full paths.
- **Formats.** JSON (schema in [`schema/report.schema.json`](schema/report.schema.json)), Markdown, HTML (one file,
  no JavaScript), SARIF 2.1.0, and POA&M CSV (`mcpxw-poam.csv`, one row per finding, with columns modeled on common
  POA&M fields; not the FedRAMP template or any other official template). CSV cells that a spreadsheet could read
  as a formula are prefixed with a single quote.
- **Discovery.** `--discover` reads only the locations in
  [`src/mcp_crosswalk/discovery/locations.py`](src/mcp_crosswalk/discovery/locations.py). Use it on your own machine.
- **Exit codes.** 0: no findings at or above `--fail-on` (default `high`). 1: findings at or above it. 2: usage or
  runtime error.

Checks are listed in [`docs/checks.md`](docs/checks.md).

### Coverage: what a static scan can and cannot assess

| Risk | Title | Static coverage | Checks |
|---|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | Assessed (static) | MCPXW-001, MCPXW-002 |
| MCP02 | Privilege Escalation via Scope Creep | Assessed (static) | MCPXW-006, MCPXW-010 |
| MCP03 | Tool Poisoning | **Not assessed (requires active analysis)** | none |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | Assessed (static) | MCPXW-003, MCPXW-004 |
| MCP05 | Command Injection & Execution | Assessed (static) | MCPXW-005, MCPXW-010 |
| MCP06 | Prompt Injection via Contextual Payloads | **Not assessed (requires active analysis)** | none |
| MCP07 | Insufficient Authentication & Authorization | Assessed (static) | MCPXW-007, MCPXW-008, MCPXW-011 |
| MCP08 | Lack of Audit and Telemetry | **Not assessed (requires active analysis)** | none |
| MCP09 | Shadow MCP Servers | Assessed only with `--allowlist` | MCPXW-009 |
| MCP10 | Context Injection & Over-Sharing | Assessed (static) | MCPXW-006 |

Tool poisoning, prompt injection, and audit logging cannot be seen in a config file. Every report lists those risks
as not assessed, so a report with no findings for them says nothing about them. Their mappings are still in the
crosswalk, and `enrich` applies them to findings from scanners that inspect live servers.

### CLI reference

```
mcpxw version
mcpxw scan [--config PATH]... [--discover] [--project-dir PATH] [--allowlist FILE]
           [--format json,md,html,sarif,poam] [--out DIR] [--fail-on high|medium|low|none]
           [--catalog-version V] [--full-paths]
mcpxw enrich INPUT.sarif [--out DIR] [--format sarif,json,md] [--catalog-version V]
mcpxw crosswalk validate [--catalog-version V] [--crosswalk-dir DIR]
mcpxw crosswalk show [--risk MCP01] [--framework nist-800-53r5|nist-csf-2.0] [--catalog-version V]
mcpxw crosswalk export --format md|csv|json [--out PATH] [--catalog-version V]
mcpxw crosswalk migrate --to VERSION --out DIR
mcpxw checks list [--format text|md] [--out PATH]
mcpxw schema export [--out DIR]
```

The allowlist is a YAML list of approved server names, package names, or URL prefixes:

```yaml
- github
- "@modelcontextprotocol/server-filesystem"
- https://mcp.internal.example.com/
```

## Limitations

- **Maintainer-reviewed, not independently validated.** All 77 mappings are maintainer-reviewed
  (`review_status: reviewed`, 2026-10-31), with each decision and its reasoning in
  [`docs/review/crosswalk-review.csv`](docs/review/crosswalk-review.csv). They have not been reviewed by OWASP,
  NIST, or an independent assessor.
- **Static and partial scanning.** Only what is written in config files is visible. Servers configured through MDM,
  enterprise policy, or other clients are not seen.
- **Heuristic secret detection.** It uses argument names, known token prefixes, and a heuristic for random URL path
  segments. It can miss secrets in unusual forms and can flag non-secrets. Treat findings as leads to verify.
- **"Assessed (static)" is not a full assessment.** It means at least one config check ran for the risk.
- **Derived federal data.** Baselines and 800-171r3 links inherit any error in NIST's OSCAL files, and say nothing
  about tailoring, overlays, FedRAMP, or CMMC.
- **`enrich` trusts the input's IDs** and does not cap its output size.
- **Beta source.** The OWASP MCP Top 10 is in beta. Titles and scope may change.

## Careful claims

The tool reports indicators relevant to controls. It never says a control is met or unmet, and its output is not an
assessment, audit, or compliance determination. A finding may be mitigated by a compensating control the scanner
cannot see, and a clean scan does not show that any control is implemented.

## Roadmap

Not built yet:

- **FedRAMP baselines.** Show FedRAMP Rev 5 LOW, MODERATE, and HIGH membership from FedRAMP's published OSCAL
  baselines, next to the NIST baselines.
- **NIST OLIR export.** Export the crosswalk in the format NIST's Online Informative References program uses, for
  submission.
- Independent practitioner review of the crosswalk.
- An OSCAL Assessment Results export.
- A GitHub Action that runs `scan` or `enrich` and uploads SARIF.
- Mappings to the NIST AI RMF, ISO/IEC 42001, and the EU AI Act.

## How it was built

Claude Code wrote the code, tests, and first-draft mappings from specifications I wrote, inside a sandbox with
enforced permission rules, a decision log, and an independent review at the end of each run. I own the design, the
crosswalk review, and release sign-off. The specifications, logs, and completion reports are in
[`docs/build-log/`](docs/build-log/).

## Related work

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/): the risk list this crosswalk maps.
- [OWASP MCP Governance & Risk Framework mapping](https://github.com/OWASP/OWASP-MCP-Governance-and-Risk-Project/blob/main/framework-mapping.md):
  maps MCP risks to the NIST AI RMF, ISO/IEC 42001, and SOC 2.
- [OWASP GenAI Security Project crosswalk](https://github.com/GenAI-Security-Project/crosswalk): maps the OWASP
  LLM and Agentic lists to many frameworks.
- [NIST COSAiS](https://csrc.nist.gov/projects/cosais): SP 800-53 control overlays for AI systems.
- Other MCP scanners: [Snyk agent-scan](https://github.com/snyk/agent-scan),
  [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner).

No other public mapping of the OWASP MCP Top 10 to SP 800-53 Rev 5 and CSF 2.0 was found in an October 2026 search.

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q
uv run pytest --cov=mcp_crosswalk --cov-branch --cov-fail-under=85
uv run mcpxw crosswalk validate
uv run python scripts/fetch_reference_data.py [ID ...]   # refresh vendored NIST files (network)
uv run mcpxw crosswalk export --format md --out docs/crosswalk.md
uv run mcpxw crosswalk export --format csv --out docs/crosswalk.csv
uv run mcpxw checks list --format md --out docs/checks.md
uv run mcpxw schema export --out schema
```

CI runs the same gate on every push and pull request. See [`CONTRIBUTING.md`](CONTRIBUTING.md),
[`SECURITY.md`](SECURITY.md), and [`docs/threat-model.md`](docs/threat-model.md).

## Attribution and licenses

- **Code:** Apache License 2.0 ([`LICENSE`](LICENSE)).
- **Crosswalk mappings, rationales, and risk summaries:** original to this project, CC BY 4.0
  ([`LICENSE-DATA.md`](LICENSE-DATA.md)).
- **OWASP MCP Top 10:** risk IDs and titles from the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
  project, licensed CC BY-NC-SA 4.0, are referenced with attribution only. No OWASP descriptive text is reproduced.
  This project is not affiliated with or endorsed by OWASP.
- **NIST SP 800-53 Rev 5 (catalog and LOW/MODERATE/HIGH/PRIVACY baselines), SP 800-171 Rev 3, and CSF 2.0:** OSCAL
  files from [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content), U.S. Government works (public
  domain in the U.S.), vendored unmodified with hashes in
  [`catalog/frameworks/SOURCES.md`](catalog/frameworks/SOURCES.md). Not affiliated with or endorsed by NIST.

See [`NOTICE`](NOTICE).
