# PROGRESS v0.2.0

## Goal (restated)
Release mcp-crosswalk 0.2.0: make the crosswalk consumable by other scanners (`mcpxw enrich` on SARIF), add federal
context (800-53 baselines, derived 800-171 Rev 3 links, POA&M CSV), prepare for the next OWASP MCP Top 10 (catalog
versions and ID migration), and close two scanner gaps (MCPXW-011, VS Code `settings.json`).
End state: N0-N8 done, full gate passing after a cache clear, independent review done, `V02_COMPLETION_REPORT.md`
written and committed, working tree clean.

## Milestones
- [x] N0: Orientation (baseline fast gate green after D30/B4: 446 passed)
- [x] N1: OWASP catalog versions and ID migration (versions.yaml, migration schema, `crosswalk migrate`, `--catalog-version` on 4 commands; synthetic 2099-test; OWASP page: still 2025 beta (D31); pytest: 480 passed)
- [x] N2: Scanner gap fixes (MCPXW-011 + 4 MCP07 mappings cite it, still 77; VS Code settings.json both shapes + 4 locations; golden diff only N2-caused; pytest: 512 passed)
- [x] N3: Federal context (5 NIST files vendored + SOURCES.md; 40 controls: L17/M31/H33/P2/none 7; 21 reqs across 23 controls; schema 1.1; pytest: 531 passed)
- [x] N4: POA&M export (`--format poam` -> mcpxw-poam.csv, 18 columns; CSV injection guard on POA&M + crosswalk CSV; redaction test covers poam; golden; pytest: 550 passed)
- [x] N5: `mcpxw enrich` (7 synthetic SARIF fixtures; round trip, tag dedup, summary, exit 0/2, offline + no URI read, official schema validation; pytest: 612 passed)
- [x] N6: Docs, positioning, version 0.2.0 (README repositioned + Related work; methodology, threat model T11-T13, CHANGELOG; docs/schema regenerated; wheel check expanded; pytest: 614 passed)
- [x] N7: Full gate and demo (caches cleared; 9/9 gates PASS: 614 passed, 99.06% branch cov, validate 77, docs no diff, pip-audit clean, build OK, WHEEL OK; demos out/demo (5 files) + out/enrich-demo (2 files), no secret leaked)
- [x] N8: Independent review and completion (13 findings: 12 fixed (R8 in part), R12 rejected (D47); 20/20 spot checks PASS; clean re-run: 9/9 gates PASS, 655 passed, 98.93% cov; demos OK; V02_COMPLETION_REPORT.md)

## Current status
Started 2026-10-07. V0.2 COMPLETE (2026-10-07): N0-N8 done. See V02_COMPLETION_REPORT.md. Next action: owner review.
