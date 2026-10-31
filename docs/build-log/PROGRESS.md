# PROGRESS

## Goal (restated)
Build `mcp-crosswalk` (CLI `mcpxw`): a versioned, schema-validated crosswalk from the OWASP MCP Top 10 to
NIST SP 800-53 Rev 5 and CSF 2.0, validated against vendored OSCAL catalogs, plus an offline, read-only static
scanner for MCP client configs that emits JSON/Markdown/HTML/SARIF findings joined to those controls.
End state: M0-M8 done, full quality gate passing, independent review done, `COMPLETION_REPORT.md` written and committed.

## Milestones
- [x] M0: Bootstrap (pytest: 1 passed; `uv run mcpxw version` -> 0.1.0; ruff/mypy clean)
- [x] M1: Reference data (both OSCAL catalogs vendored + SOURCES.md; OWASP list matches live page; pytest: 26 passed)
- [x] M2: Crosswalk (75 mappings, `crosswalk validate` clean; negative test per rule; pytest: 63 passed)
- [x] M3: Parsing and discovery (all clients + JSONC + malformed + hostile fixtures; 3 platforms; real-home audit test; pytest: 122 passed)
- [x] M4: Checks and engine (10 checks; kitchen sink triggers all 10; validate passes vs real registry; pytest: 352 passed)
- [x] M5: Reporters (JSON vs schema, SARIF vs official OASIS schema, HTML self-contained + escaped; pytest: 381 passed)
- [x] M6: CLI and end-to-end (all commands; exit codes 0/1/2 tested; 11 golden reports; determinism; pytest: 413 passed)
- [x] M7: Hardening and docs (offline/redaction/read-only/static-audit tests; pip-audit clean; full gate PASS; 421 passed, 99.19% branch cov; wheel check OK)
- [x] M8: Independent review and completion (12 review findings all fixed; final clean gate PASS: 446 passed, 99.22% cov; demo in out/demo; COMPLETION_REPORT.md)

## Current status
Started 2026-10-07T16:46Z. BUILD COMPLETE (2026-10-07). All milestones M0-M8 done. See COMPLETION_REPORT.md. Next action: owner review.
Post-build: owner crosswalk corrections applied (D29): 77 mappings; gates re-run, all PASS (446 passed, 99.22% cov).
