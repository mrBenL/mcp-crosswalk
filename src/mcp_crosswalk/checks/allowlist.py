"""MCPXW-009: server not on the allowlist (runs only when ``--allowlist`` is given)."""

from __future__ import annotations

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.checks.launch import package_launch, package_name
from mcp_crosswalk.models import Finding, ServerEntry
from mcp_crosswalk.redact import redact_url


def run(check: Check, entry: ServerEntry, context: CheckContext) -> list[Finding]:
    allowlist = context.allowlist
    if allowlist is None:
        return []
    if entry.name in allowlist.names:
        return []
    launch = package_launch(entry.command, entry.args)
    package = package_name(launch) if launch else None
    if package and package in allowlist.names:
        return []
    if entry.url and any(entry.url.startswith(prefix) for prefix in allowlist.url_prefixes):
        return []
    identity = []
    if package:
        identity.append(f"package {package}")
    if entry.url:
        identity.append(f"url {redact_url(entry.url)}")
    detail = f" ({', '.join(identity)})" if identity else ""
    evidence = f"server name, package, and URL not on the allowlist{detail}"
    return [make_finding(check, entry, "allowlist", evidence)]


CHECK = Check(
    id="MCPXW-009",
    title="Server not on the allowlist",
    risk_ids=("MCP09",),
    severity="medium",
    description=(
        "Runs only when --allowlist FILE is given (a YAML list of approved server names, package "
        "names, or URL prefixes). Flags any configured server when none of its name, launched "
        "package name, or URL matches an entry. Without an allowlist this check does not run; "
        "instead every server is listed in the report's server inventory for manual review."
    ),
    remediation=(
        "Review the server. If it is approved, add its package name or URL prefix to the allowlist "
        "through your change process; otherwise remove it from the client config and follow up "
        "with the owner of the machine or repository."
    ),
    run_fn=run,
    requires_allowlist=True,
)
