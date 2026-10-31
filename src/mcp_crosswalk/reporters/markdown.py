"""Markdown report.

Every value that came from a config file goes through ``esc``: invisible control characters are
made visible, HTML special characters become entities (so a Markdown renderer cannot be tricked
into emitting raw HTML), and Markdown control characters are backslash-escaped. The tool's own text
(titles, remediation, control names) only needs ``light``.
"""

from __future__ import annotations

import html
import re

from mcp_crosswalk.models import Report
from mcp_crosswalk.reporters.common import (
    control_label,
    group_by_severity,
    neutralize,
    risk_titles,
)

# Square brackets are left alone so redaction markers stay verbatim; escaping parentheses is
# enough to stop inline links and images from forming. Line-start markers (#, +, -) need no
# escaping because untrusted values never begin a line.
_MD_SPECIAL = re.compile(r"([\\`*_()!|~])")


def esc(value: object) -> str:
    """Escape untrusted text for inline Markdown (including table cells)."""
    text = " ".join(neutralize(str(value)).split())
    return _MD_SPECIAL.sub(r"\\\1", html.escape(text, quote=False))


def light(value: str) -> str:
    """Escape trusted text: table pipes and tildes (which some renderers treat as strikethrough)."""
    return re.sub(r"([|~])", r"\\\1", value)


def _row(cells: list[object]) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def render(report: Report) -> str:
    titles = risk_titles(report)
    s = report.summary
    lines = [
        "# MCP configuration scan report",
        "",
        f"> {report.disclaimer}",
        "",
        f"- Generated: {report.generated_at}",
        f"- Tool: {report.tool.name} {report.tool.version}",
        f"- OWASP MCP Top 10 version: {report.catalog.owasp_version}",
        "",
        "## Summary",
        "",
        "| Severity | Findings |",
        "|---|---|",
        _row(["High", s.by_severity.get("high", 0)]),
        _row(["Medium", s.by_severity.get("medium", 0)]),
        _row(["Low", s.by_severity.get("low", 0)]),
        _row(["**Total**", s.total_findings]),
        "",
        f"Servers inventoried: {s.total_servers}. Config files read: "
        f"{sum(1 for i in report.inputs if i.status == 'ok')} of {len(report.inputs)}.",
        "",
        "### Inputs",
        "",
        "| Path | Client | Status | Servers | Error |",
        "|---|---|---|---|---|",
    ]
    for item in report.inputs:
        lines.append(
            _row([esc(item.path), item.client, item.status, item.servers, esc(item.error or "")])
        )
    lines += [
        "",
        "## Coverage matrix",
        "",
        "Risks that cannot be assessed from configuration files are listed as not assessed; "
        "they are not omitted and a lack of findings for them means nothing. "
        + report.coverage_note,
        "",
        "| Risk | Title | Status | Checks | Findings |",
        "|---|---|---|---|---|",
    ]
    for row in report.coverage:
        lines.append(
            _row(
                [
                    row.risk_id,
                    light(row.title),
                    row.status,
                    ", ".join(row.check_ids) or "-",
                    row.findings,
                ]
            )
        )
    lines += ["", "## Findings", ""]
    groups = group_by_severity(report)
    if not groups:
        lines += ["No findings for the risks that were assessed statically.", ""]
    for group in groups:
        lines += [f"### Severity: {group.severity.upper()} ({len(group.findings)})", ""]
        for f in group.findings:
            risks = ", ".join(f"{r} ({light(titles.get(r, ''))})" for r in f.risk_ids)
            lines += [
                f"#### {f.check_id}: {light(f.title)}",
                "",
                f"- Severity: {f.severity.upper()}",
                f"- Server: {esc(f.server)} ({f.client})",
                f"- Source: {esc(f.source_path)}",
                f"- Risks: {risks}",
                f"- Evidence: {esc(f.evidence)}",
                "- Relevant controls (indicators, not a compliance determination):",
            ]
            lines += [f"  - {light(control_label(c))}" for c in f.controls] or ["  - none mapped"]
            lines += [f"- Remediation: {light(f.remediation)}", f"- Finding ID: {f.id}", ""]
    lines += [
        "## Server inventory",
        "",
        "Every configured server, for manual review. Environment and header values are redacted "
        "unless they are variable references.",
        "",
        "| Server | Client | Scope | Transport | Command or URL | Env keys | Source |",
        "|---|---|---|---|---|---|---|",
    ]
    for server in report.servers:
        target = server.url if server.url else " ".join([server.command or "", *server.args])
        name = f"{server.name} [{server.project}]" if server.project else server.name
        lines.append(
            _row(
                [
                    esc(name),
                    server.client,
                    server.scope,
                    server.transport,
                    esc(target.strip()),
                    esc(", ".join(sorted(server.env))),
                    esc(server.source_path),
                ]
            )
        )
    lines.append("")
    return "\n".join(lines)
