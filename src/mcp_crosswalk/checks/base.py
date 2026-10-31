"""Check definition and finding construction shared by all checks."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from mcp_crosswalk.models import Finding, ServerEntry, Severity


@dataclass(frozen=True)
class Allowlist:
    """Approved server names, package names, and URL prefixes (for MCPXW-009)."""

    entries: tuple[str, ...]

    @property
    def url_prefixes(self) -> tuple[str, ...]:
        return tuple(e for e in self.entries if "://" in e)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(e for e in self.entries if "://" not in e)


@dataclass(frozen=True)
class CheckContext:
    allowlist: Allowlist | None = None


RunFn = Callable[["Check", ServerEntry, CheckContext], list[Finding]]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    risk_ids: tuple[str, ...]
    severity: Severity
    description: str
    remediation: str
    run_fn: RunFn = field(repr=False)
    requires_allowlist: bool = False

    def run(self, entry: ServerEntry, context: CheckContext | None = None) -> list[Finding]:
        return self.run_fn(self, entry, context or CheckContext())


def finding_id(check_id: str, source_path: str, server: str, evidence_key: str) -> str:
    """First 12 hex characters of SHA-256 over check, source path, server name, and evidence key."""
    material = "\x1f".join([check_id, source_path, server, evidence_key])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def make_finding(
    check: Check,
    entry: ServerEntry,
    evidence_key: str,
    evidence: str,
    severity: Severity | None = None,
) -> Finding:
    """Build a finding. ``evidence`` must already be redacted. Controls are joined by the engine."""
    key = f"{entry.project}::{evidence_key}" if entry.project else evidence_key
    return Finding(
        id=finding_id(check.id, entry.source_path, entry.name, key),
        check_id=check.id,
        title=check.title,
        severity=severity or check.severity,
        risk_ids=list(check.risk_ids),
        server=entry.name,
        client=entry.client,
        source_path=entry.source_path,
        project=entry.project,
        evidence=evidence if not entry.project else f"[project {entry.project}] {evidence}",
        remediation=check.remediation,
        controls=[],
    )
