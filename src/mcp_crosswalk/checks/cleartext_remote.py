"""MCPXW-007: remote server over cleartext ``http://`` to a non-loopback host."""

from __future__ import annotations

from urllib.parse import urlsplit

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.models import Finding, ServerEntry
from mcp_crosswalk.redact import redact_url

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    if not entry.url:
        return []
    try:
        parts = urlsplit(entry.url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return []
    if parts.scheme.lower() != "http" or host in LOOPBACK_HOSTS:
        return []
    evidence = f"url {redact_url(entry.url)} uses cleartext HTTP to host {host or '(none)'}"
    return [make_finding(check, entry, "url:http", evidence)]


CHECK = Check(
    id="MCPXW-007",
    title="Remote server over cleartext HTTP",
    risk_ids=("MCP07",),
    severity="high",
    description=(
        "Flags remote (HTTP or SSE) servers whose URL uses http:// to any host other than "
        "localhost, 127.0.0.1, or ::1. Tokens, tool arguments, results, and session identifiers "
        "then cross the network unencrypted and can be read or altered in transit."
    ),
    remediation=(
        "Use an https:// endpoint with a valid certificate. If the server cannot offer TLS, reach "
        "it only through an encrypted tunnel or a local TLS-terminating proxy on a loopback "
        "address."
    ),
    run_fn=run,
)
