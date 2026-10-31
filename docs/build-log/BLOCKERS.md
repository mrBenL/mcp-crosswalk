# BLOCKERS

Commands or actions denied by permissions or the sandbox, why they were needed, and the fallback used.

## B1. Compound `cd ... && python3 - <<EOF` denied (M1)
- **What:** a Bash call of the form `cd <root> && python3 -I - <<'EOF' ... EOF` to inspect the downloaded OSCAL
  JSON structure was refused by the `dontAsk` permission mode (not pre-approved as a whole command).
- **Why needed:** read-only inspection of the catalog structure before writing the loader.
- **What I did instead:** wrote the same read-only inspection script to the session scratchpad (temp dir) and ran
  it as a plain `python3 -I <script> <project root>` command, which is on the allow list. From then on I run all
  commands from the project root without `cd` prefixes or heredocs. Not a bypass: the action (running Python
  read-only over a project file) is explicitly allowed; only the command shape was not.

## B2. Other command shapes refused by `dontAsk` mode (no capability lost)
Each was replaced by a plainly allowed form; none was retried in a disguised form.
- `sed -i ...` chained after other commands (M4): edited the files with the Edit tool instead.
- `uv run mcpxw scan; echo "exit=$?"` (M6): exit codes are asserted in tests (`tests/test_cli_scan.py`) instead.
- `MCPXW_UPDATE_GOLDEN=1 uv run pytest ...` (M6): replaced the env var with a pytest option,
  `uv run pytest tests/test_cli_scan.py --update-golden` (defined in `tests/conftest.py`).
- `git check-ignore -v ...` (M8): confirmed ignore status with `git status --short --ignored out dist`.

## B3. Command shapes refused during the owner corrections (D29), no capability lost
Nothing was retried in a disguised form.
- `rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage` before the gate run: not run. The gate was run without
  clearing caches. Every tool re-checks file contents, and pytest-cov rewrites `.coverage` each run, so the results
  are still valid. However, this run was not a clean-cache run, unlike the M8 final run.
- A chained command that rebuilt `$TMPDIR/demo/kitchen_sink.json` from the fixture by importing `tests/conftest.py`
  and then scanned it: not run. The materialized demo config from the original M8 build was still in `$TMPDIR/demo/`
  (the fixture has not changed since), so I ran the original demo command against it as a single command.
- A chained `crosswalk validate; ... export && git diff` call: each gate command was run on its own instead.
- A Python heredoc to print control statements: the same read-only script was written to the session scratchpad
  and run with `python -I`, as in B1.

## B4. `ruff format --check .` failed on the `CORRECTIONS.md` mount point (v0.2, N0)
- **What:** the baseline fast gate failed: `io: Permission denied (os error 13) --> CORRECTIONS.md:1:1`.
- **Why:** `CORRECTIONS.md` is a sandbox-protected character device in the project root (like the D1 mount points).
- **What I did instead:** added `/CORRECTIONS.md` to `.gitignore` (D30). I did not read, edit, or work around the
  protection on the file itself. The gate then passed: 446 tests.

## B5. Command shapes refused during v0.2 (no capability lost)
Nothing was retried in a disguised form. Each was redone with a plainly allowed tool.
- Chained commands that ran a Python heredoc and then `cat`/`ruff`/`mypy` in one call (N1 fixtures, N2b source
  edits, an N8 test append): refused by `dontAsk` mode. The files were written or edited with the Write and Edit
  tools, and the checks run as separate commands.
- `sed -i` for the version bump (N6): edited with the Edit tool instead.
- Standalone heredocs that only appended to `DECISIONS.md`/`BLOCKERS.md` and single-purpose `python3 -` edit scripts
  ran without a prompt early on. From N2 onward I switched to the Edit tool, which matches the spec's guidance.
