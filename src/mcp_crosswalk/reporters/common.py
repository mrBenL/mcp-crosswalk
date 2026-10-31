"""Helpers shared by the human-readable reporters."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from mcp_crosswalk.federal import SP800_171R3_LABEL
from mcp_crosswalk.models import ControlRef, Finding, Report, Severity

SEVERITIES: tuple[Severity, ...] = ("high", "medium", "low")

# Bidirectional-text and zero-width controls can make hostile server names display as something
# else ("Trojan Source"). Human-readable reports show them as visible code points instead.
_INVISIBLE_CONTROLS = frozenset(
    [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
    + ["\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u061c", "\ufeff"]
)


def neutralize(text: str) -> str:
    """Replace bidi/zero-width controls and other C0/C1 control characters with visible markers."""
    out = []
    for ch in text:
        code = ord(ch)
        if ch in _INVISIBLE_CONTROLS or (code < 0x20 and ch not in "\t\n") or 0x7F <= code < 0xA0:
            out.append(f"<U+{code:04X}>")
        else:
            out.append(ch)
    return "".join(out)


FRAMEWORK_LABELS = {"nist-800-53r5": "SP 800-53r5", "nist-csf-2.0": "CSF 2.0"}


@dataclass(frozen=True)
class SeverityGroup:
    severity: Severity
    findings: list[Finding]


def group_by_severity(report: Report) -> list[SeverityGroup]:
    groups: dict[Severity, list[Finding]] = defaultdict(list)
    for finding in report.findings:
        groups[finding.severity].append(finding)
    return [SeverityGroup(sev, groups[sev]) for sev in SEVERITIES if groups[sev]]


def federal_note(control: ControlRef) -> str:
    """Derived baseline and 800-171r3 context for an 800-53 control ('' for CSF)."""
    if control.framework != "nist-800-53r5":
        return ""
    note = f"baselines: {', '.join(control.baselines) or 'none'}"
    if control.sp800_171r3_derived:
        note += f"; {SP800_171R3_LABEL}: {', '.join(control.sp800_171r3_derived)}"
    return note


def control_label(control: ControlRef) -> str:
    framework = FRAMEWORK_LABELS[control.framework]
    note = federal_note(control)
    return (
        f"{framework} {control.control_id} {control.title} "
        f"({control.risk_id}; {control.relationship}, {control.confidence} confidence)"
        + (f" [{note}]" if note else "")
    )


def risk_titles(report: Report) -> dict[str, str]:
    return {row.risk_id: row.title for row in report.coverage}


def not_assessed(report: Report) -> list[str]:
    return [row.risk_id for row in report.coverage if row.status != "Assessed (static)"]
