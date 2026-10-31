"""Scan engine: parse inputs, run checks, join the crosswalk, and build the report."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from mcp_crosswalk import __version__, catalogs, federal, versions
from mcp_crosswalk.checks.base import Allowlist, Check, CheckContext
from mcp_crosswalk.crosswalk import load_version_crosswalk
from mcp_crosswalk.discovery.adapters import read_config
from mcp_crosswalk.models import (
    DISCLAIMER,
    SEVERITY_ORDER,
    CatalogInfo,
    ClientId,
    ControlRef,
    CoverageRow,
    CoverageStatus,
    CrosswalkFile,
    Finding,
    FrameworkInfo,
    InputRecord,
    OwaspCatalog,
    Report,
    Scope,
    ServerEntry,
    Severity,
    Summary,
    ToolInfo,
)
from mcp_crosswalk.models import Mapping as CrosswalkMapping
from mcp_crosswalk.redact import redact_server

ASSESSED: CoverageStatus = "Assessed (static)"
NOT_ASSESSED: CoverageStatus = "Not assessed (requires active analysis)"
NO_ALLOWLIST: CoverageStatus = "Not assessed (no allowlist provided; review the server inventory)"


class AllowlistError(ValueError):
    """The allowlist file is missing or malformed."""


@dataclass(frozen=True)
class ScanTarget:
    path: Path
    client: ClientId | None = None
    scope: Scope | None = None


def load_allowlist(path: Path) -> Allowlist:
    """Load a YAML list of allowed server names, package names, or URL prefixes."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise AllowlistError(f"cannot read allowlist {path}: {exc}") from exc
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise AllowlistError(f"allowlist {path} must be a YAML list of strings")
    return Allowlist(entries=tuple(sorted({item.strip() for item in data if item.strip()})))


def control_ref(risk_id: str, mapping: CrosswalkMapping) -> ControlRef:
    """A crosswalk mapping as a report control entry, with derived federal context."""
    entry = catalogs.lookup(mapping.framework, mapping.control_id)
    return ControlRef(
        risk_id=risk_id,
        framework=mapping.framework,
        control_id=mapping.control_id,
        title=entry.title if entry else "",
        relationship=mapping.relationship,
        confidence=mapping.confidence,
        baselines=federal.baselines_for(mapping.framework, mapping.control_id),
        sp800_171r3_derived=federal.sp800_171r3_for(mapping.framework, mapping.control_id),
    )


def _controls_for(
    finding: Finding,
    crosswalk: Mapping[str, CrosswalkFile],
) -> list[ControlRef]:
    refs: dict[tuple[str, str, str], ControlRef] = {}
    for risk_id in finding.risk_ids:
        cw_file = crosswalk.get(risk_id)
        if cw_file is None:
            continue
        for mapping in cw_file.mappings:
            if finding.check_id not in mapping.check_ids:
                continue
            refs[(risk_id, mapping.framework, mapping.control_id)] = control_ref(risk_id, mapping)
    return [refs[key] for key in sorted(refs)]


def _finding_sort_key(finding: Finding) -> tuple[int, str, str, str, str, str]:
    return (
        -SEVERITY_ORDER[finding.severity],
        finding.check_id,
        finding.source_path,
        finding.server,
        finding.evidence,
        finding.id,
    )


def build_coverage(
    owasp: OwaspCatalog,
    checks: Iterable[Check],
    findings: list[Finding],
    allowlist_given: bool,
) -> list[CoverageRow]:
    rows = []
    check_list = list(checks)
    for risk in sorted(owasp.risks, key=lambda r: r.short_id):
        risk_checks = [c for c in check_list if risk.short_id in c.risk_ids]
        runnable = [c for c in risk_checks if allowlist_given or not c.requires_allowlist]
        if not risk_checks:
            status = NOT_ASSESSED
        elif not runnable:
            status = NO_ALLOWLIST
        else:
            status = ASSESSED
        rows.append(
            CoverageRow(
                risk_id=risk.short_id,
                title=risk.title,
                status=status,
                check_ids=sorted(c.id for c in risk_checks),
                findings=sum(1 for f in findings if risk.short_id in f.risk_ids),
            )
        )
    return rows


def run_checks(
    entries: Iterable[ServerEntry],
    checks: Iterable[Check],
    context: CheckContext,
) -> list[Finding]:
    findings: dict[str, Finding] = {}
    check_list = list(checks)
    for entry in entries:
        for check in check_list:
            if check.requires_allowlist and context.allowlist is None:
                continue
            for finding in check.run(entry, context):
                findings.setdefault(finding.id, finding)
    return list(findings.values())


def scan(
    targets: Iterable[ScanTarget],
    allowlist: Allowlist | None = None,
    now: datetime | None = None,
    catalog_version: str | None = None,
) -> Report:
    """Scan config files and return the canonical report.

    ``catalog_version`` selects the OWASP catalog (default from ``versions.yaml``); check risk IDs
    are translated into that version's numbering.
    """
    crosswalk = load_version_crosswalk(catalog_version)
    owasp = versions.load_owasp(catalog_version)
    checks = versions.checks_for(catalog_version)

    inputs: list[InputRecord] = []
    entries: list[ServerEntry] = []
    seen: set[str] = set()
    for target in targets:
        try:
            key = str(target.path.resolve())
        except (OSError, RuntimeError):
            key = str(target.path)
        if key in seen:
            continue
        seen.add(key)
        record, parsed = read_config(target.path, client=target.client, scope=target.scope)
        inputs.append(record)
        entries.extend(parsed)

    entries.sort(key=lambda e: (e.source_path, e.project or "", e.name))
    context = CheckContext(allowlist=allowlist)
    raw_findings = run_checks(entries, checks, context)
    findings = sorted(
        (f.model_copy(update={"controls": _controls_for(f, crosswalk)}) for f in raw_findings),
        key=_finding_sort_key,
    )

    by_severity: dict[Severity, int] = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        by_severity[finding.severity] += 1

    timestamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return Report(
        tool=ToolInfo(name="mcp-crosswalk", version=__version__),
        generated_at=timestamp,
        catalog=CatalogInfo(
            owasp_version=owasp.version,
            frameworks=[
                FrameworkInfo(id=fw, source_sha256=catalogs.load_catalog(fw).source_sha256)
                for fw in catalogs.FRAMEWORKS
            ],
        ),
        disclaimer=DISCLAIMER,
        inputs=sorted(inputs, key=lambda i: i.path),
        servers=[redact_server(e) for e in entries],
        findings=findings,
        coverage=build_coverage(owasp, checks, findings, allowlist is not None),
        summary=Summary(
            by_severity=by_severity,
            total_findings=len(findings),
            total_servers=len(entries),
        ),
    )
