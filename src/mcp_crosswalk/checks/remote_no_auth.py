"""MCPXW-008: remote server with no static auth header configured."""

from __future__ import annotations

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.models import Finding, ServerEntry
from mcp_crosswalk.redact import is_secret_header, redact_url, url_secrets


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    if not entry.url or entry.transport not in {"http", "sse"}:
        return []
    if any(is_secret_header(name) for name in entry.headers):
        return []
    if url_secrets(entry.url):
        return []  # static credential in the URL; MCPXW-002 reports it
    evidence = (
        f"url {redact_url(entry.url)} has no static auth header; "
        "verify whether OAuth is negotiated at runtime"
    )
    return [make_finding(check, entry, "auth:none", evidence)]


CHECK = Check(
    id="MCPXW-008",
    title="Remote server with no static auth header (verify)",
    risk_ids=("MCP07",),
    severity="low",
    description=(
        "Flags remote (HTTP or SSE) servers with no credential header (Authorization, X-API-Key, "
        "Cookie, or another credential-named header) in the config. This is an item to verify, not "
        "a defect: MCP clients may negotiate OAuth with the server at runtime, which a static scan "
        "cannot see. It matters most for servers that expose sensitive tools."
    ),
    remediation=(
        "Confirm how the server authenticates callers. Prefer OAuth via the client's built-in "
        "support, or a header that references a secret (for example 'Bearer ${env:TOKEN}'). "
        "Do not connect to remote MCP servers that accept unauthenticated tool calls."
    ),
    run_fn=run,
)
