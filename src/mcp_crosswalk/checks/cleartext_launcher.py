"""MCPXW-011: cleartext ``http://`` remote URL inside a stdio launcher.

Stdio-to-remote bridges such as ``mcp-remote``, ``supergateway``, and ``mcp-proxy`` run locally but
forward every tool call to a URL given on their command line. The config entry has no ``url`` key,
so MCPXW-007 does not see it.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.checks.cleartext_remote import LOOPBACK_HOSTS
from mcp_crosswalk.models import Finding, ServerEntry, Severity
from mcp_crosswalk.redact import redact_url

PROXY_PACKAGES = ("mcp-remote", "supergateway", "mcp-proxy")
_HTTP_URL = re.compile(r"(?i)\bhttp://[^\s\"'<>`]+")
_ANY_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://\S*")


def _cleartext_urls(text: str) -> list[tuple[str, str]]:
    """``(url, host)`` for each ``http://`` URL in the text whose host is not loopback."""
    found = []
    for match in _HTTP_URL.finditer(text):
        url = match.group(0)
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            continue
        if host and host not in LOOPBACK_HOSTS:
            found.append((url, host))
    return found


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    if not entry.command:
        return []
    # Bridge names count in the command or package arguments, not inside a URL's host or path.
    launch_text = _ANY_URL.sub(" ", " ".join([entry.command, *entry.args])).lower()
    proxy = next((p for p in PROXY_PACKAGES if p in launch_text), None)
    severity: Severity = "high" if proxy else "medium"
    places = [("command", entry.command)] + [(f"arg {i}", a) for i, a in enumerate(entry.args)]
    findings = []
    for place, text in places:
        for index, (url, host) in enumerate(_cleartext_urls(text)):
            via = f" via {proxy}" if proxy else ""
            evidence = (
                f"stdio launcher {place} carries cleartext URL {redact_url(url)} (host {host}){via}"
            )
            key = f"launcher-http:{place}:{index}"
            findings.append(make_finding(check, entry, key, evidence, severity=severity))
    return findings


CHECK = Check(
    id="MCPXW-011",
    title="Cleartext remote URL inside a stdio launcher",
    risk_ids=("MCP07",),
    severity="high",
    description=(
        "Flags stdio servers whose command or arguments contain an http:// URL to any host other "
        "than localhost, 127.0.0.1, or ::1. Bridges such as mcp-remote, supergateway, and "
        "mcp-proxy run locally but forward every tool call, result, and credential to that URL, "
        "so the traffic crosses the network unencrypted. High severity when the launcher names "
        "one of those bridges; medium for any other stdio command that carries such a URL."
    ),
    remediation=(
        "Point the bridge at an https:// endpoint with a valid certificate. If the remote server "
        "cannot offer TLS, reach it only through an encrypted tunnel or a TLS-terminating proxy on "
        "a loopback address, and do not send tokens to it over plain HTTP."
    ),
    run_fn=run,
)
