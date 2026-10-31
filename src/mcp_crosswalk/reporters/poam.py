"""POA&M-style CSV: one row per finding, with columns modeled on common POA&M fields.

This is not the FedRAMP POA&M template or any other official template. Rows are ordered by
severity (high first), then finding ID. Every cell goes through ``csvsafe.safe_cell`` because
config values are attacker-controlled. UTF-8, header row, RFC 4180 quoting with CRLF line ends.
"""

from __future__ import annotations

import csv
import io

from mcp_crosswalk.csvsafe import safe_cell
from mcp_crosswalk.models import SEVERITY_ORDER, Finding, Report

COLUMNS = [
    "POA&M ID",
    "Weakness Name",
    "Weakness Description",
    "Source",
    "OWASP MCP Risk",
    "Asset",
    "Client",
    "Config File",
    "Severity",
    "Related 800-53 Controls",
    "Related CSF 2.0 Subcategories",
    "800-53 Baselines",
    "Recommended Remediation",
    "Status",
    "Date Identified",
    "Scheduled Completion Date",
    "Milestones",
    "Comments",
]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _row(finding: Finding, report: Report, titles: dict[str, str]) -> list[str]:
    sp800_53 = [c for c in finding.controls if c.framework == "nist-800-53r5"]
    csf = [c for c in finding.controls if c.framework == "nist-csf-2.0"]
    baselines: dict[str, list[str]] = {}
    for control in sp800_53:
        baselines.setdefault(control.control_id, control.baselines)
    return [
        finding.id,
        finding.title,
        f"{finding.evidence.rstrip('.')}. {report.disclaimer}",
        f"mcpxw {report.tool.version} {finding.check_id}",
        "; ".join(f"{r} {titles.get(r, '')}".strip() for r in finding.risk_ids),
        finding.server,
        finding.client,
        finding.source_path,
        finding.severity,
        "; ".join(_unique([c.control_id for c in sp800_53])),
        "; ".join(_unique([c.control_id for c in csf])),
        "; ".join(f"{cid}: {', '.join(b) or 'none'}" for cid, b in baselines.items()),
        finding.remediation,
        "Open",
        report.generated_at[:10],
        "",
        "",
        "",
    ]


def render(report: Report) -> str:
    titles = {row.risk_id: row.title for row in report.coverage}
    findings = sorted(report.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.id))
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(COLUMNS)
    for finding in findings:
        writer.writerow([safe_cell(cell) for cell in _row(finding, report, titles)])
    return buffer.getvalue()
