"""SARIF 2.1.0 report: one rule per check, one result per finding."""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import quote

from mcp_crosswalk import __version__, versions
from mcp_crosswalk.checks.base import Check
from mcp_crosswalk.crosswalk import load_version_crosswalk
from mcp_crosswalk.models import Finding, Report

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"high": "error", "medium": "warning", "low": "note"}
# GitHub code scanning reads this property to rank results (0.1-10).
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0"}
# Base ID for config paths under the home directory when paths are shortened to ~ (path privacy).
HOME_URI_BASE = "HOME"


def artifact_uri(source_path: str) -> str:
    """A valid SARIF artifact URI for a config path (file URI when absolute)."""
    if PureWindowsPath(source_path).drive:
        return PureWindowsPath(source_path).as_uri()
    path = Path(source_path)
    if path.is_absolute():
        return path.as_uri()
    return quote(path.as_posix())


def artifact_location(source_path: str) -> dict[str, str]:
    """SARIF artifactLocation; a ``~`` path becomes a URI relative to the ``HOME`` base ID."""
    if source_path.startswith(("~/", "~\\")):
        rest = source_path[2:].replace("\\", "/")
        return {"uri": quote(rest), "uriBaseId": HOME_URI_BASE}
    return {"uri": artifact_uri(source_path)}


@cache
def _file_lines(source_path: str) -> tuple[str, ...]:
    try:
        return tuple(Path(source_path).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return ()


def _key_line(lines: tuple[str, ...], key: str, start: int = 0) -> int | None:
    patterns = {json.dumps(key), json.dumps(key, ensure_ascii=False)}
    regexes = [re.compile(re.escape(p) + r"\s*:") for p in patterns]
    for index in range(start, len(lines)):
        if any(r.search(lines[index]) for r in regexes):
            return index
    return None


def find_start_line(source_path: str, server: str, project: str | None) -> int | None:
    """1-based line where the server's key appears in the file, or None if it cannot be found."""
    lines = _file_lines(source_path)
    if project:
        project_line = _key_line(lines, project)
        if project_line is None:
            return None
        start = project_line
    else:
        start = _top_level_container_line(lines)
    found = _key_line(lines, server, start)
    return found + 1 if found is not None else None


def _top_level_container_line(lines: tuple[str, ...]) -> int:
    """Line of the least-indented ``mcpServers``/``servers``/``mcp.servers`` container key."""
    container = re.compile(r'^(\s*)"(?:mcpServers|servers|mcp\.servers)"\s*:')
    best: tuple[int, int] | None = None
    for index, line in enumerate(lines):
        match = container.match(line)
        if match and (best is None or len(match.group(1)) < best[0]):
            best = (len(match.group(1)), index)
    return best[1] if best else 0


def _rule_controls(checks: tuple[Check, ...], catalog_version: str) -> dict[str, list[str]]:
    crosswalk = load_version_crosswalk(catalog_version)
    controls: dict[str, set[str]] = {check.id: set() for check in checks}
    for cw_file in crosswalk.values():
        for mapping in cw_file.mappings:
            for check_id in mapping.check_ids:
                controls.setdefault(check_id, set()).add(mapping.control_id)
    return {check_id: sorted(ids) for check_id, ids in controls.items()}


def _rules(disclaimer: str, catalog_version: str) -> list[dict[str, Any]]:
    checks = versions.checks_for(catalog_version)
    controls = _rule_controls(checks, catalog_version)
    rules = []
    for check in checks:
        tags = ["security", "mcp", *check.risk_ids, *controls.get(check.id, [])]
        rules.append(
            {
                "id": check.id,
                "name": re.sub(r"[^A-Za-z0-9]+", " ", check.title).title().replace(" ", ""),
                "shortDescription": {"text": check.title},
                "fullDescription": {"text": check.description},
                "help": {
                    "text": f"{check.remediation}\n\n{disclaimer}",
                    "markdown": f"{check.remediation}\n\n_{disclaimer}_",
                },
                "defaultConfiguration": {"level": LEVELS[check.severity]},
                "properties": {
                    "tags": tags,
                    "risk_ids": list(check.risk_ids),
                    "security-severity": SECURITY_SEVERITY[check.severity],
                    "requires_allowlist": check.requires_allowlist,
                },
            }
        )
    return rules


def _result(finding: Finding, rule_index: dict[str, int], real: Finding) -> dict[str, Any]:
    """One SARIF result. ``real`` is the same finding with unshortened paths, for line lookup."""
    location: dict[str, Any] = {"artifactLocation": artifact_location(finding.source_path)}
    line = find_start_line(real.source_path, real.server, real.project)
    if line is not None:
        location["region"] = {"startLine": line}
    return {
        "ruleId": finding.check_id,
        "ruleIndex": rule_index[finding.check_id],
        "level": LEVELS[finding.severity],
        "message": {
            "text": f"{finding.title} (server '{finding.server}'): {finding.evidence}. "
            "Indicator relevant to the mapped controls; not a compliance determination."
        },
        "locations": [{"physicalLocation": location}],
        "partialFingerprints": {"mcpxwFindingId/v1": finding.id},
        "properties": {
            "severity": finding.severity,
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "server": finding.server,
            "client": finding.client,
            "risk_ids": finding.risk_ids,
            "controls": [c.model_dump(mode="json") for c in finding.controls],
            "tags": [*finding.risk_ids, *sorted({c.control_id for c in finding.controls})],
        },
    }


def build(report: Report, line_source: Report | None = None) -> dict[str, Any]:
    """The SARIF log. ``line_source`` is the report before path shortening, if it was shortened."""
    originals = (line_source or report).findings
    rules = _rules(report.disclaimer, report.catalog.owasp_version)
    rule_index = {rule["id"]: index for index, rule in enumerate(rules)}
    pairs = zip(report.findings, originals, strict=True)
    results = [_result(shown, rule_index, real) for shown, real in pairs]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "mcp-crosswalk",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": rules,
            }
        },
        "results": results,
        "columnKind": "unicodeCodePoints",
        "properties": {
            "disclaimer": report.disclaimer,
            "generated_at": report.generated_at,
            "owasp_version": report.catalog.owasp_version,
            "coverage": [row.model_dump(mode="json") for row in report.coverage],
            "coverage_note": report.coverage_note,
        },
    }
    if any(
        r["locations"][0]["physicalLocation"]["artifactLocation"].get("uriBaseId") for r in results
    ):
        run["originalUriBaseIds"] = {
            HOME_URI_BASE: {
                "description": {"text": "The user's home directory, not recorded for privacy."}
            }
        }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def render(report: Report, line_source: Report | None = None) -> str:
    _file_lines.cache_clear()
    return json.dumps(build(report, line_source), indent=2, sort_keys=True) + "\n"
