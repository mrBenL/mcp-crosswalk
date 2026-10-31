# Contributing

Thanks for helping improve mcp-crosswalk. Contributions to the crosswalk data are as valuable as code.

## Setup

```bash
uv sync                      # creates .venv with runtime and dev dependencies
uv run mcpxw version
```

## Before you open a pull request

Run the same checks CI would:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --cov=mcp_crosswalk --cov-branch --cov-fail-under=85
uv run mcpxw crosswalk validate
```

If you changed crosswalk YAML, check registry metadata, or models, regenerate the generated files and commit them
(tests fail if they are stale):

```bash
uv run mcpxw crosswalk export --format md --out docs/crosswalk.md
uv run mcpxw crosswalk export --format csv --out docs/crosswalk.csv
uv run mcpxw checks list --format md --out docs/checks.md
uv run mcpxw schema export --out schema
uv run pytest tests/test_cli_scan.py --update-golden   # only when report output changes intentionally
```

Review the golden diff before committing it.

## Changing the crosswalk

- Read the control statement in the vendored catalog (`mcpxw crosswalk show`, or the OSCAL JSON) before adding a
  mapping. The validator only proves an ID exists, not that it fits.
- Write the rationale in your own words (20 to 400 characters) and name the MCP mechanism: config file, stdio
  command, tool description, remote transport.
- Use the relationship vocabulary and direction in `docs/methodology.md`. Prefer a precise enhancement over its base
  control when it fits. Use `confidence: low` for plausible but indirect mappings.
- Do not copy text from the OWASP MCP Top 10 (CC BY-NC-SA 4.0). Reference IDs and titles only.
- New mappings start as `review_status: draft`.

## Adding a check

1. Add a module under `src/mcp_crosswalk/checks/` defining `CHECK = Check(...)` with an ID, title, risk IDs,
   severity, description, remediation (your own words), and a `run` function. Register it in `checks/registry.py`.
2. Put any secret-shaped value only through `redact.redact()` before it reaches evidence text.
3. Reference the check from at least one crosswalk mapping for each risk it lists.
4. Add positive, negative, and reference-is-not-a-secret tests, and make the kitchen-sink fixture trigger it.

## Test fixtures

- Never put anything secret-shaped in a fixture. Use placeholders such as `__FAKE_GITHUB_PAT__`; `tests/conftest.py`
  substitutes fake values built at runtime.
- Claude Code protects `.mcp.json`, `.vscode/`, and `.claude/` inside a working tree, so fixtures use neutral names
  (`claude_code_project.json`, `vscode_project.jsonc`) and tests copy them to their real names under `tmp_path`.
- Tests must never read the real home directory or real MCP configs. Discovery tests inject fake roots.

## Safety rules for the code

- No network access, subprocesses, or dynamic code execution in `src/` (enforced by `tests/test_hardening.py`).
- Write files only inside the user's `--out` directory.
- Autoescape everything in HTML; escape untrusted values in Markdown.
- Never print unredacted values to the terminal.
