# Build log

This folder holds the records of how mcp-crosswalk was built. They are kept for transparency. You do not need
them to use the tool.

## How the project was built

Claude Code (Anthropic's coding agent) wrote the code, tests, and first-draft crosswalk mappings. It ran
autonomously from specifications I wrote, under a governed process:

- **Written specifications.** [`BUILD_SPEC.md`](BUILD_SPEC.md) (v0.1.0) and [`V02_SPEC.md`](V02_SPEC.md) (v0.2.0)
  defined what to build, the acceptance criteria, and the quality gates. [`CLAUDE.md`](CLAUDE.md) defined the
  operating rules: stay inside the project, never run MCP servers or `npx`/`uvx`/`docker`, never read real
  secrets or real MCP configs, never publish, never weaken a test or gate to make it pass, and never invent a
  control ID. [`LAUNCH.md`](LAUNCH.md) is the setup and launch checklist I followed.
- **Sandbox and permission rules.** The agent ran in an OS-level sandbox with `.claude/settings.json` (kept at
  the repo root). Reads of credential stores and MCP client configs were blocked, network access was limited to
  PyPI and GitHub, and publishing, `git push`, `git config`, history rewrites, and package-runner commands were
  denied.
- **Decision and blocker logs.** Every judgment call the agent made without me is in
  [`DECISIONS.md`](DECISIONS.md). Every command the sandbox or permissions refused, and the safe alternative
  used, is in [`BLOCKERS.md`](BLOCKERS.md). The agent was told never to retry a blocked action in another form.
- **Milestones and gates.** Each milestone ended with lint, format, strict type checks, and tests passing, and a
  commit. Progress is in [`PROGRESS.md`](PROGRESS.md) and [`PROGRESS_V02.md`](PROGRESS_V02.md).
- **Independent review.** At the end of each run, a separate read-only Claude agent with a fresh context reviewed
  the work against the spec and safety rules, and spot-checked mappings and derived data against the vendored NIST
  files. Findings and their dispositions are in the completion reports and `DECISIONS.md`.
- **Completion reports.** [`COMPLETION_REPORT.md`](COMPLETION_REPORT.md) (v0.1.0) and
  [`V02_COMPLETION_REPORT.md`](V02_COMPLETION_REPORT.md) (v0.2.0) record gate results and acceptance criteria.

## What I own

- **Design and scope:** the problem, the specifications, the safety rules, and what is out of scope.
- **Crosswalk review:** the mappings are draft until I review them. My first corrections after v0.1.0 (add
  AC-6(7) and AU-10, narrow SI-15, change an AC-6 relationship) are in commit `05f7e17`. The full review of all 77
  mappings uses the worksheet in [`../review/`](../review/). A crosswalk file shows `review_status: reviewed` only
  after I have reviewed it.
- **Sign-off:** before preparing the repo for publication, I had every gate and both demos re-run on 2026-10-31
  and compared with the completion reports. The one mismatch (new `pip-audit` findings in dev-only dependencies)
  was fixed. I approve each release.

## Reading these files

These are historical records. Their instructions (for example "never ask the owner a question") applied only to
the autonomous runs. File paths inside them refer to the original layout, where these files sat at the repo root.
