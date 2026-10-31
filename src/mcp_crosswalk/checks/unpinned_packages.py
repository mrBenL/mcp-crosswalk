"""MCPXW-003: unpinned package launch (npx, bunx, pnpm dlx, uvx, pipx run, docker/podman run)."""

from __future__ import annotations

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.checks.launch import package_launch, unpinned_reason
from mcp_crosswalk.models import Finding, ServerEntry
from mcp_crosswalk.redact import redact_known_tokens


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    launch = package_launch(entry.command, entry.args)
    if launch is None:
        return []
    reason = unpinned_reason(launch)
    if reason is None:
        return []
    spec = redact_known_tokens(launch.spec)
    evidence = f"{launch.launcher} {spec} ({reason})"
    return [make_finding(check, entry, f"package:{launch.spec}", evidence)]


CHECK = Check(
    id="MCPXW-003",
    title="Unpinned package launch",
    risk_ids=("MCP04",),
    severity="medium",
    description=(
        "Flags stdio servers that fetch and run a package at launch without pinning an exact "
        "version: npx, bunx, or pnpm dlx with no @version, @latest, a version range, or a "
        "dist-tag; uvx or pipx run without ==version or @version; docker or podman run with an "
        "image that has no tag or uses :latest and has no @sha256: digest. Local paths and VCS "
        "URLs are not flagged."
    ),
    remediation=(
        "Pin the exact package version (for example @scope/server@1.4.2 or server==1.4.2) or the "
        "container image digest (image@sha256:...), review upgrades deliberately, and consider a "
        "vetted internal registry mirror for MCP server packages."
    ),
    run_fn=run,
)
