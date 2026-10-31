"""MCPXW-004: auto-confirmed install (``npx -y`` / ``--yes``)."""

from __future__ import annotations

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.checks.launch import basename, package_launch
from mcp_crosswalk.models import Finding, ServerEntry

_YES = frozenset({"-y", "--yes", "--yes=true"})


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    if basename(entry.command) != "npx":
        return []
    launch = package_launch(entry.command, entry.args)
    package_index = entry.args.index(launch.spec) if launch and launch.spec in entry.args else None
    launcher_args = entry.args[:package_index] if package_index is not None else entry.args
    for arg in launcher_args:
        if arg in _YES:
            target = f" {launch.spec}" if launch else ""
            return [make_finding(check, entry, "npx-yes", f"npx {arg}{target}")]
    return []


CHECK = Check(
    id="MCPXW-004",
    title="Auto-confirmed package install",
    risk_ids=("MCP04",),
    severity="low",
    description=(
        "Flags npx launches with -y or --yes before the package name. The flag suppresses the "
        "install prompt, so whatever version the registry serves is downloaded and run on every "
        "client start without the user seeing it."
    ),
    remediation=(
        "Install the MCP server package ahead of time at a reviewed, pinned version and launch the "
        "installed binary, or at minimum pin an exact version so -y cannot pull an unreviewed "
        "release."
    ),
    run_fn=run,
)
