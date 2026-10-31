# Pre-publish checklist

Work through this before creating the public repository. Items marked **(blocking)** must be done first. Results
recorded here were checked on 2026-10-31 at commit `fb395ad` plus the changes in the commit that added this file.

## 1. Employer policy (blocking)

- [ ] Confirm that my employer's intellectual property and outside-activities policies allow publishing this
      project under my name, and whether any approval or disclosure is required. Check whether the policy covers
      work done on personal time and equipment, and whether the GRC subject matter overlaps with my job duties.
      Keep the answer in writing.

## 2. Secrets in the full git history (blocking)

- [x] Pattern scan of every blob in history (382 blobs, all branches) and every commit message, for GitHub, AWS,
      Slack, OpenAI, Anthropic, Google, and PyPI tokens, JWTs, private keys, and quoted password/secret/token
      assignments. **Result: no matches.** Test fixtures hold placeholders such as `__FAKE_GITHUB_PAT__`; the fake
      secrets are built by concatenation at test time and never committed.
- [ ] Re-run with a dedicated scanner before pushing, for example `gitleaks git --redact -v .` from a separate
      terminal (gitleaks is not a project dependency). Resolve or document every hit.
- [x] No `.env` file, key file, or real client config was ever committed. Of the 174 paths in history
      (`git log --all --name-only --format= | sort -u`), the only sensitive-looking names are
      `.claude/settings.json` (the build's permission rules), two check modules, and a synthetic golden file.

## 3. Personal information

- [x] Local username: not found in any blob or commit message.
- [x] Home-directory paths: only synthetic ones (`/home/alex`, `/Users/alex`, `C:\Users\alex`) in tests and
      fixtures. Commit `0fc39fe` contains the test strings `/home/ben` and `/home/benjamin` (later replaced). They are
      examples, not real paths.
- [x] Reports show the home directory as `~` by default, so demo output and screenshots do not reveal a user name.
      Re-check any report you paste into the README or a post.
- [ ] Commit metadata: all commits use `Ben Luthy <support@benluthy.com>`. This address becomes public with the
      history. Decide whether that is the address you want on record.
- [ ] The build logs in `docs/build-log/` name me as owner and describe my setup steps. Read them once as a
      stranger would, and confirm nothing in them is private.

## 4. Licenses

- [x] Code: Apache-2.0 (`LICENSE`), declared in `pyproject.toml` and included in the wheel with `LICENSE-DATA.md`
      and `NOTICE`.
- [x] Data: crosswalk mappings, rationales, and risk summaries under CC BY 4.0 (`LICENSE-DATA.md`).
- [x] Runtime dependencies are permissive and compatible with Apache-2.0: typer, rich, pydantic, pydantic-core,
      pyyaml, annotated-types, annotated-doc, typing-inspection, markdown-it-py, mdurl (MIT); jinja2, MarkupSafe,
      colorama (Windows only) (BSD-3-Clause); pygments (BSD-2-Clause); shellingham (ISC); typing-extensions (PSF-2.0).
- [x] NIST OSCAL files are U.S. Government works, vendored unmodified with SHA-256 hashes in
      `catalog/frameworks/SOURCES.md`. `NOTICE` now lists all of them.
- [ ] OWASP MCP Top 10 is CC BY-NC-SA 4.0. Only risk IDs and titles may be used. Read the ten risk summaries in
      `catalog/owasp-mcp/` once and confirm they are original wording, not paraphrases close to OWASP's text.
- [ ] `tests/schemas/sarif-schema-2.1.0.json` is the OASIS SARIF 2.1.0 schema, fetched from
      `oasis-tcs/sarif-spec`. Check that repository's license and add an entry to `NOTICE` if it requires one.

## 5. Placeholders and loose ends

- [x] Replace the GitHub owner placeholder in `README.md` (CI badge and clone URL) with the GitHub account name.
- [ ] Add a security contact to `SECURITY.md`, and `authors` and `urls` to `pyproject.toml`.
- [ ] Move the four files the build sandbox kept read-only into `docs/build-log/`, from a terminal outside
      Claude Code: `git mv CLAUDE.md BUILD_SPEC.md V02_SPEC.md LAUNCH.md docs/build-log/`, then commit. The links
      in `docs/build-log/README.md` already point there.
- [ ] After that move, `.claude/settings.json` still denies edits to `./CLAUDE.md` and the other old paths. Decide
      whether to publish `.claude/` as part of the governance record (it holds no secrets) or remove it.
- [ ] `.gitignore` lists the sandbox mount points (`/.bashrc`, `/.gitconfig`, `/CORRECTIONS.md`, and others).
      They are harmless in a public repo, but you can drop them once you no longer build in the sandbox.

## 6. Quality and claims

- [x] Crosswalk review complete (2026-10-31): all ten files are `review_status: reviewed`, and the disclaimer in
      reports says the mappings are maintainer-reviewed.
- [ ] Push to a private repository first and confirm CI passes. Python 3.11 and 3.13 have not been run locally;
      only 3.12 has.
- [ ] Re-check the scanner comparison table in the README against each project's current README (last checked
      2026-10-31; agent-audit-kit names only some of its 14 frameworks).
- [ ] Run the full gate on a clean checkout: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy`,
      `uv run pytest --cov=mcp_crosswalk --cov-branch --cov-fail-under=85`, `uv run mcpxw crosswalk validate`,
      `uv run pip-audit`, `uv build`.

## 7. First release (after the repository is public)

- [ ] Move the `[Unreleased]` entries in `CHANGELOG.md` under a version number and bump the version.
- [ ] Generate an SBOM and sign the release artifacts before tagging.
