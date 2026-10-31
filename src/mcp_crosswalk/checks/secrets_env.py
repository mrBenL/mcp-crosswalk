"""MCPXW-001: literal secret in ``env`` values."""

from __future__ import annotations

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.models import Finding, ServerEntry
from mcp_crosswalk.redact import (
    find_known_tokens,
    is_reference,
    is_secret_name,
    looks_like_literal_secret,
    redact,
)


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    findings = []
    for key, value in sorted(entry.env.items()):
        if is_reference(value):
            continue
        by_name = is_secret_name(key) and looks_like_literal_secret(value)
        by_prefix = bool(find_known_tokens(value))
        if by_name or by_prefix:
            why = "known credential prefix" if by_prefix else "secret-like variable name"
            evidence = f"env {key} = {redact(value)} ({why})"
            findings.append(make_finding(check, entry, f"env:{key}", evidence))
    return findings


CHECK = Check(
    id="MCPXW-001",
    title="Literal secret in server environment variables",
    risk_ids=("MCP01",),
    severity="high",
    description=(
        "Flags an `env` value that is stored as a literal in the config file when the variable "
        "name suggests a credential (token, secret, key, password, passwd, pat, credential, auth) "
        "or the value starts with a known credential prefix (ghp_, gho_, github_pat_, sk-, "
        "sk-ant-, xoxb-, xoxp-, AKIA, glpat-, AIza). References such as ${VAR}, ${env:VAR}, "
        "${input:id}, $VAR, %VAR%, and {{...}} are not flagged. Names ending in a locator word "
        "(_URL, _PATH, _FILE, _ID, ...) and values that are paths, numbers, or booleans are not "
        "flagged by name alone."
    ),
    remediation=(
        "Remove the literal value from the config file. Reference the credential from the "
        "environment or a secret manager (for example ${env:NAME} or an input prompt), rotate the "
        "exposed credential, and prefer short-lived, narrowly scoped tokens for MCP servers."
    ),
    run_fn=run,
)
