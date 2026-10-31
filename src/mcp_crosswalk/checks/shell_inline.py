"""MCPXW-005: shell interpreter as the server command with an inline script."""

from __future__ import annotations

import re

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.checks.launch import basename
from mcp_crosswalk.models import Finding, ServerEntry

_POSIX_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "fish"})
_CMD_SHELLS = frozenset({"cmd"})
_POWERSHELLS = frozenset({"powershell", "pwsh"})
_POSIX_INLINE = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")  # -c, -lc, -ic, ...
_CMD_INLINE = frozenset({"/c", "/k"})
_PS_INLINE = frozenset({"-c", "-command", "-encodedcommand", "-enc", "-ec", "-e"})


def _inline_flag(shell: str, args: list[str]) -> str | None:
    for arg in args:
        lowered = arg.lower()
        if shell in _POSIX_SHELLS and _POSIX_INLINE.match(arg):
            return arg
        if shell in _CMD_SHELLS and lowered in _CMD_INLINE:
            return arg
        if shell in _POWERSHELLS and lowered in _PS_INLINE:
            return arg
    return None


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    shell = basename(entry.command)
    if shell not in _POSIX_SHELLS | _CMD_SHELLS | _POWERSHELLS:
        return []
    flag = _inline_flag(shell, entry.args)
    if flag is None:
        return []
    position = entry.args.index(flag)
    script = entry.args[position + 1] if position + 1 < len(entry.args) else ""
    evidence = f"{shell} {flag} <inline script, {len(script)} characters>"
    return [make_finding(check, entry, f"shell:{flag}", evidence)]


CHECK = Check(
    id="MCPXW-005",
    title="Shell interpreter launches server with inline script",
    risk_ids=("MCP05",),
    severity="high",
    description=(
        "Flags servers whose command is a shell (bash, sh, zsh, dash, fish, cmd, powershell, pwsh) "
        "given an inline script flag (-c, /c, /k, -Command, -EncodedCommand). The config then "
        "holds arbitrary shell code that runs at every client launch, which is hard to review, "
        "easy to tamper with, and widens command-injection exposure. The script text is not "
        "reproduced in reports."
    ),
    remediation=(
        "Launch the MCP server binary directly with explicit arguments instead of through a shell. "
        "If a wrapper is unavoidable, put it in a reviewed, version-controlled script file with "
        "restricted permissions and reference that file."
    ),
    run_fn=run,
)
