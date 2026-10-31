"""Canonical JSON report."""

from __future__ import annotations

import json

from mcp_crosswalk.models import Report


def render(report: Report) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
