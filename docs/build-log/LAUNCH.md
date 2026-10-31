# LAUNCH.md: Ben's 10-minute setup, then hands off

Claude Code reads `CLAUDE.md` automatically and is told to read `BUILD_SPEC.md`. `.claude/settings.json` enforces the safety rules
at the tool level, so they don't rely on Claude following instructions alone.

## What protects your machine

| Layer | What it does |
|---|---|
| OS sandbox (`sandbox` block) | Shell commands can write only inside this project folder and a temp dir. Network is limited to PyPI and GitHub. Credential and MCP-config paths are unreadable. Commands can't fall back to running unsandboxed, and Claude Code refuses to start if the sandbox is unavailable. |
| Permission rules (`permissions` block) | Denies sudo, package managers, curl/wget, docker, npx, git push/config/reset, publishing, and edits to its own instruction files. |
| `dontAsk` mode (launch flag) | Anything not pre-approved is refused automatically, so the build never stalls waiting for you and never escalates. |
| `CLAUDE.md` rules | No bypassing blocks, no deleting outside what it created, no real configs or secrets, no publishing. |

## Requirements

- **macOS, Linux, or WSL2.** Native Windows has no sandbox, so these settings make Claude Code refuse to start there. That's intended.
  On Windows, use WSL2 and put the project in the Linux filesystem (`~/projects/...`), not under `/mnt/c`.
- **Linux/WSL2 only:** `sudo apt-get install bubblewrap socat`. On Ubuntu 24.04+, see the AppArmor note on the Claude Code sandboxing docs page if `/sandbox` reports a problem.
- Python 3.11+ (`python3 --version`), [uv](https://docs.astral.sh/uv/) (`uv --version`), git with `user.name` and `user.email` set, and Claude Code (current version).

## Setup (once)

```bash
mkdir -p ~/projects/mcp-crosswalk && cd ~/projects/mcp-crosswalk
# copy in: CLAUDE.md, BUILD_SPEC.md, LAUNCH.md, and the .claude/ folder (with settings.json)
git init
git add -A && git commit -m "Build instructions"
```

You run `git init` yourself because the sandbox protects `.git/config`, so Claude can't create a repo, only commit to one.

## Preflight (2 minutes, once)

1. Start Claude Code in the folder: `claude`
2. Accept the **trust this folder** prompt. Project allow rules only apply after you trust the folder.
3. Run `/sandbox` and confirm there's no Dependencies-only tab (that would mean something's missing).
4. Ask Claude: `Run: touch ~/sandbox-probe`. It should fail with *Operation not permitted* (macOS) or *Read-only file system* (Linux/WSL2). If it succeeds, stop, delete `~/sandbox-probe`, and fix the sandbox before continuing.
5. Exit with `/exit`.

## Launch

```bash
cd ~/projects/mcp-crosswalk
claude --permission-mode dontAsk
```

Paste this as the first message:

```
Read CLAUDE.md and BUILD_SPEC.md in full, then build the mcp-crosswalk MVP end to end, autonomously,
following every rule in CLAUDE.md. Do not ask me anything; record decisions in DECISIONS.md and blockers
in BLOCKERS.md. Work through milestones M0 to M8 in order, run the quality gates, do the independent
review, write COMPLETION_REPORT.md, and finish with BUILD COMPLETE or BUILD PARTIAL and the summary.
```

**Headless alternative** (no interactive window; prints only the final summary):

```bash
claude -p "<the same prompt>" --permission-mode dontAsk
```

## If it stops early

The only expected interruption is a usage limit or a closed terminal. To resume, start it again the same way and send:

```
Resume the build. Read PROGRESS.md, DECISIONS.md, and BLOCKERS.md, check git log, and continue from the first unfinished milestone.
```

## When it's done

Read `COMPLETION_REPORT.md` first. Then:
- Open `out/demo/` to see sample reports in all four formats.
- Review `crosswalk/MCP01.yaml` ... `MCP10.yaml`. They are all `review_status: draft` until you sign off.
- Work through the "Owner checklist before going public" in the report. That includes confirming your employer's IP and outside-activity policy before you push anything public.
