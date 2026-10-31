"""MCPXW-006: over-broad filesystem scope (root or home directory passed to a server)."""

from __future__ import annotations

import re

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.models import Finding, ServerEntry, Severity
from mcp_crosswalk.redact import redact_known_tokens

_BROAD_EXACT = frozenset(
    {
        "/",
        "~",
        "~/",
        "~\\",
        "$home",
        "$home/",
        "${home}",
        "${home}/",
        "${env:home}",
        "${env:userprofile}",
        "%userprofile%",
        "%userprofile%\\",
        "%userprofile%/",
        "/root",
        "/root/",
    }
)
_BROAD_PATTERNS = (
    re.compile(r"^[A-Za-z]:[\\/]?$"),  # C:\  C:/  C:
    re.compile(r"^/Users/[^/\\]+/?$"),
    re.compile(r"^/home/[^/\\]+/?$"),
    re.compile(r"^[A-Za-z]:[\\/]Users[\\/][^/\\]+[\\/]?$", re.IGNORECASE),
)


def is_broad_path(value: str) -> bool:
    candidate = value.strip().strip("\"'")
    if candidate.lower() in _BROAD_EXACT:
        return True
    return any(p.match(candidate) for p in _BROAD_PATTERNS)


def _path_value(arg: str) -> str:
    """For ``--flag=value`` return value; otherwise the arg itself."""
    if arg.startswith("-") and "=" in arg:
        return arg.split("=", 1)[1]
    return arg


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    broad = [(i, a) for i, a in enumerate(entry.args) if is_broad_path(_path_value(a))]
    if not broad:
        return []
    others = [entry.command or ""] + [a for i, a in enumerate(entry.args) if (i, a) not in broad]
    is_filesystem = any("filesystem" in part.lower() for part in others)
    severity: Severity = "high" if is_filesystem else "medium"
    kind = "filesystem server" if is_filesystem else "server"
    findings = []
    for index, arg in broad:
        evidence = (
            f"args[{index}] = {redact_known_tokens(arg)} ({kind} granted a root or home path)"
        )
        findings.append(make_finding(check, entry, f"arg:{index}", evidence, severity=severity))
    return findings


CHECK = Check(
    id="MCPXW-006",
    title="Over-broad filesystem scope",
    risk_ids=("MCP02", "MCP10"),
    severity="high",
    description=(
        "Flags an argument that resolves to a filesystem root or a home directory (/, ~, $HOME, "
        "%USERPROFILE%, C:\\, /Users/<name>, /home/<name>, C:\\Users\\<name>). Severity is high "
        "when the server's command or package name contains 'filesystem' and medium for any other "
        "server. Such scope exposes SSH keys, cloud credentials, and unrelated data to the agent."
    ),
    remediation=(
        "Scope the server to the specific project directories it needs, preferably read-only, and "
        "keep credential directories (~/.ssh, ~/.aws, ~/.config) outside every allowed root."
    ),
    run_fn=run,
)
