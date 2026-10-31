"""Pydantic v2 models: OWASP catalog, crosswalk files, server entries, findings, and the report."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FrameworkId = Literal["nist-800-53r5", "nist-csf-2.0"]
Relationship = Literal["equal", "subset_of", "superset_of", "intersects_with"]
Confidence = Literal["high", "medium", "low"]
Severity = Literal["high", "medium", "low"]
ReviewStatus = Literal["draft", "reviewed"]
ClientId = Literal["claude_desktop", "claude_code", "cursor", "vscode", "windsurf", "generic"]
Scope = Literal["user", "project", "unknown"]
Transport = Literal["stdio", "http", "sse", "unknown"]
InputStatus = Literal["ok", "parse_error", "read_error"]
CoverageStatus = Literal[
    "Assessed (static)",
    "Not assessed (requires active analysis)",
    "Not assessed (no allowlist provided; review the server inventory)",
]

SEVERITY_ORDER: dict[str, int] = {"high": 3, "medium": 2, "low": 1}

COVERAGE_NOTE = (
    "Assessed (static) means at least one configuration-indicator check ran for the risk; "
    "it is not a complete assessment of the risk."
)

DISCLAIMER = (
    "Findings are indicators relevant to the listed controls. They are not a compliance "
    "determination. Mappings are maintainer-reviewed and not endorsed by OWASP or NIST."
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- OWASP catalog -------------------------------------------------------------------------


class OwaspRisk(StrictModel):
    id: str = Field(pattern=r"^MCP\d{2}:\d{4}$")
    short_id: str = Field(pattern=r"^MCP\d{2}$")
    title: str
    aliases: list[str] = Field(default_factory=list)
    summary: str
    source_url: str


class OwaspCatalog(StrictModel):
    version: str
    retrieved: str
    source_url: str
    license_note: str
    risks: list[OwaspRisk]

    def by_short_id(self) -> dict[str, OwaspRisk]:
        return {risk.short_id: risk for risk in self.risks}


CatalogStatus = Literal["beta", "final", "test"]


class CatalogVersion(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    file: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*\.yaml$",
        description="Catalog file name in catalog/owasp-mcp/",
    )
    status: CatalogStatus
    retrieved: str
    crosswalk: str | None = Field(
        default=None,
        description="Crosswalk directory relative to the data root, or null if not authored yet",
    )


class CatalogVersions(StrictModel):
    """``catalog/owasp-mcp/versions.yaml``: the available OWASP catalog versions."""

    default: str
    versions: list[CatalogVersion]


class MigrationEntry(StrictModel):
    to: str | None = Field(
        pattern=r"^MCP\d{2}$", description="New risk ID, or null when the risk is retired"
    )
    note: str = Field(min_length=1, description="Why the risk moved or was retired")


class Migration(StrictModel):
    """``catalog/owasp-mcp/migrations/<from>__to__<to>.yaml``: risk ID changes between versions."""

    from_version: str
    to_version: str
    map: dict[str, MigrationEntry] = Field(
        description="Every risk ID of from_version, mapped to its ID in to_version (or retired)"
    )


# --- Crosswalk ------------------------------------------------------------------------------


class Mapping(StrictModel):
    framework: FrameworkId
    control_id: str = Field(description="Display form, e.g. IA-5(7) or PR.AA-01")
    relationship: Relationship = Field(
        description="NIST OLIR convention: the OWASP MCP risk (focal) relative to the control "
        "(reference)"
    )
    confidence: Confidence
    rationale: str = Field(description="1-2 sentences, 20 to 400 characters")
    check_ids: list[str] = Field(default_factory=list)


class CrosswalkFile(StrictModel):
    risk_id: str = Field(pattern=r"^MCP\d{2}$")
    catalog_version: str
    review_status: ReviewStatus
    mappings: list[Mapping]


# --- Config parsing -------------------------------------------------------------------------


class ServerEntry(StrictModel):
    name: str
    client: ClientId
    source_path: str
    scope: Scope = "unknown"
    transport: Transport = "unknown"
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    raw_keys: list[str] = Field(default_factory=list)
    project: str | None = Field(
        default=None,
        description="Project path for Claude Code projects.<path>.mcpServers entries",
    )


class InputRecord(StrictModel):
    path: str
    client: ClientId
    status: InputStatus
    servers: int = 0
    error: str | None = None


# --- Findings and report --------------------------------------------------------------------


class ControlRef(StrictModel):
    risk_id: str = Field(description="The OWASP risk whose crosswalk mapping supplied this control")
    framework: FrameworkId
    control_id: str
    title: str
    relationship: Relationship
    confidence: Confidence
    baselines: list[str] = Field(
        default_factory=list,
        description="SP 800-53 Rev 5 baselines (LOW, MODERATE, HIGH, PRIVACY) that include this "
        "control; derived from the vendored resolved-profile catalogs; empty for CSF",
    )
    sp800_171r3_derived: list[str] = Field(
        default_factory=list,
        description="800-171r3 (derived via source 800-53 control): requirement numbers whose "
        "source controls include exactly this control. Derived, not an authored mapping",
    )


class Finding(StrictModel):
    id: str = Field(pattern=r"^[0-9a-f]{12}$")
    check_id: str
    title: str
    severity: Severity
    risk_ids: list[str]
    server: str
    client: ClientId
    source_path: str
    project: str | None = Field(
        default=None, description="Claude Code project path when the server is project-scoped"
    )
    evidence: str
    remediation: str
    controls: list[ControlRef] = Field(default_factory=list)


class ToolInfo(StrictModel):
    name: str
    version: str


class FrameworkInfo(StrictModel):
    id: FrameworkId
    source_sha256: str


class CatalogInfo(StrictModel):
    owasp_version: str
    frameworks: list[FrameworkInfo]


class CoverageRow(StrictModel):
    risk_id: str
    title: str
    status: CoverageStatus
    check_ids: list[str]
    findings: int


class Summary(StrictModel):
    by_severity: dict[Severity, int]
    total_findings: int
    total_servers: int


class Report(StrictModel):
    # 1.1 (v0.2.0) adds optional fields only: ControlRef.baselines and .sp800_171r3_derived.
    schema_version: Literal["1.1"] = "1.1"
    tool: ToolInfo
    generated_at: str
    catalog: CatalogInfo
    disclaimer: str
    inputs: list[InputRecord]
    servers: list[ServerEntry]
    findings: list[Finding]
    coverage: list[CoverageRow]
    coverage_note: str = COVERAGE_NOTE
    summary: Summary
