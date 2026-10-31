# Security policy

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue for a vulnerability.

- Contact: _maintainer contact to be added before the first public release_ (see the owner checklist in
  [`docs/build-log/V02_COMPLETION_REPORT.md`](docs/build-log/V02_COMPLETION_REPORT.md)).
- Include: affected version, a minimal config file or command that reproduces the issue (use fake secrets only),
  what you expected, and what happened.
- Expect an acknowledgement within 5 business days. Fixes for confirmed issues are released as a patch version with
  a `CHANGELOG.md` entry; reporters are credited unless they ask not to be.

## Scope

In scope:

- The `mcpxw` CLI and the `mcp_crosswalk` Python package.
- Ways a hostile MCP config file could make the tool execute code, make a network request, write outside the `--out`
  directory, crash instead of recording a parse error, or emit a secret in unredacted form.
- Script or HTML injection into generated reports (HTML, Markdown, SARIF, JSON).
- Incorrect or misleading crosswalk data that could cause a reader to draw a compliance conclusion the tool does not
  support (report these as ordinary issues unless they are being actively exploited).

Out of scope:

- Vulnerabilities in the MCP servers or clients that the tool scans. Report those to their maintainers.
- Findings that are missed by the heuristic checks (false negatives) are bugs, not vulnerabilities; please open an
  ordinary issue.
- The vendored NIST catalogs' content.

## Design properties

The design properties this project aims for, each backed by tests, are listed in `docs/threat-model.md`:
read-only, offline at runtime, never executes config contents, detected secrets redacted in every output, hostile
input escaped, careful claims. Secret detection is heuristic; a secret in an unusual form can be missed.
