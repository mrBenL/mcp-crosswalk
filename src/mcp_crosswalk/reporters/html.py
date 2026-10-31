"""Single-file HTML report: inline CSS, no JavaScript, no external assets, autoescaped."""

from __future__ import annotations

from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from mcp_crosswalk.models import Report
from mcp_crosswalk.reporters.common import (
    FRAMEWORK_LABELS,
    federal_note,
    group_by_severity,
    neutralize,
    not_assessed,
    risk_titles,
)


def _finalize(value: Any) -> Any:
    """Applied to every ``{{ }}`` value before autoescaping."""
    return neutralize(value) if isinstance(value, str) else value


def _environment() -> Environment:
    return Environment(
        loader=PackageLoader("mcp_crosswalk", "reporters/templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        finalize=_finalize,
    )


def render(report: Report) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(
        report=report,
        groups=group_by_severity(report),
        titles=risk_titles(report),
        not_assessed=not_assessed(report),
        framework_labels=FRAMEWORK_LABELS,
        federal_note=federal_note,
        inputs_ok=sum(1 for i in report.inputs if i.status == "ok"),
    )
