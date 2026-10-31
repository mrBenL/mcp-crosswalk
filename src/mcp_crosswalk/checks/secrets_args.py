"""MCPXW-002: literal secret in ``args``, ``command``, URL, or ``headers``."""

from __future__ import annotations

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.models import Finding, ServerEntry
from mcp_crosswalk.redact import (
    classify_args,
    find_known_tokens,
    is_reference,
    is_secret_header,
    redact,
    redact_command_line,
    url_secrets,
)

_LABELS = {
    "header": "credential header",
    "inline": "secret in command text",
    "assignment": "secret-named assignment",
    "token": "known credential prefix",
    "url": "credential in URL",
}


def _arg_findings(check: Check, entry: ServerEntry) -> list[Finding]:
    """Flag exactly the arguments that the report inventory redacts (shared classifier)."""
    findings = []
    for index, (redacted, kind) in enumerate(classify_args(entry.args)):
        if kind is None:
            continue
        key = f"arg:{index}"
        if kind == "url":
            secrets = url_secrets(entry.args[index])
            for where, secret in secrets:
                evidence = f"args[{index}] URL {where} = {redact(secret)}"
                findings.append(make_finding(check, entry, f"{key}:{where}", evidence))
            if secrets:
                continue
        if kind == "pair":
            evidence = f"args[{index - 1}..{index}] {entry.args[index - 1]} {redacted}"
        elif kind == "header":
            evidence = f"args[{index}] header {redacted}"
        else:
            evidence = f"args[{index}] {redacted} ({_LABELS[kind]})"
        findings.append(make_finding(check, entry, key, evidence))
    if entry.command:
        redacted_command = redact_command_line(entry.command)
        if redacted_command != entry.command:
            evidence = f"command {redacted_command} (secret in command text)"
            findings.append(make_finding(check, entry, "command", evidence))
    return findings


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    findings = _arg_findings(check, entry)
    if entry.url:
        for where, secret in url_secrets(entry.url):
            evidence = f"url {where} = {redact(secret)}"
            findings.append(make_finding(check, entry, f"url:{where}", evidence))
    for name, value in sorted(entry.headers.items()):
        if is_reference(value):
            continue
        if is_secret_header(name) or find_known_tokens(value):
            evidence = f"header {name}: {redact(value)}"
            findings.append(make_finding(check, entry, f"header:{name}", evidence))
    return findings


CHECK = Check(
    id="MCPXW-002",
    title="Literal secret in server arguments, URL, or headers",
    risk_ids=("MCP01",),
    severity="high",
    description=(
        "Flags credentials written literally into a server's launch arguments or command (for "
        "example --api-key=VALUE, --token VALUE, a bare NAME=VALUE such as docker -e "
        "API_TOKEN=VALUE, a 'Authorization: ...' header argument, or a value with a known "
        "credential prefix), into a remote URL (userinfo password, a secret-named query parameter "
        "such as api_key or token, or a long random-looking path segment), or into a credential "
        "header such as Authorization, X-API-Key, or Cookie. Command-line arguments are also "
        "visible to other local users through process listings. References such as ${VAR} or "
        "'Bearer ${env:TOKEN}' are not flagged. Exactly the values this check flags are the ones "
        "redacted in the report's server inventory."
    ),
    remediation=(
        "Move the credential out of args, URLs, and headers into an environment reference or "
        "secret store, rotate the exposed value, and use a header reference such as "
        "'Authorization: Bearer ${env:TOKEN}' or the client's OAuth support for remote servers."
    ),
    run_fn=run,
)
