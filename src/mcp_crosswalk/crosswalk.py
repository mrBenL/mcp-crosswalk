"""Load, validate, and export the OWASP MCP Top 10 to NIST crosswalk."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mcp_crosswalk import catalogs, federal, versions
from mcp_crosswalk.catalogs import FRAMEWORK_NAMES, CatalogEntry
from mcp_crosswalk.checks.registry import check_risk_index
from mcp_crosswalk.csvsafe import safe_row
from mcp_crosswalk.models import DISCLAIMER, CrosswalkFile, OwaspCatalog
from mcp_crosswalk.resources import crosswalk_dir

MIN_800_53 = 3
MIN_CSF = 2
RATIONALE_MIN = 20
RATIONALE_MAX = 400

Lookup = Callable[[str, str], CatalogEntry | None]


class CrosswalkError(RuntimeError):
    """Raised when the crosswalk cannot be loaded because it is invalid."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("crosswalk is invalid:\n" + "\n".join(problems))
        self.problems = problems


def load_owasp_catalog(path: Path | None = None) -> OwaspCatalog:
    """Load an OWASP catalog file, or the default version's catalog when no path is given."""
    if path is None:
        return versions.load_owasp()
    return OwaspCatalog.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _format_validation_error(error: ValidationError) -> list[str]:
    messages = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "<root>"
        messages.append(f"schema: {location}: {item['msg']}")
    return messages


@dataclass
class _Loaded:
    files: dict[str, CrosswalkFile] = field(default_factory=dict)  # keyed by file stem
    problems: list[str] = field(default_factory=list)


def _load_files(directory: Path) -> _Loaded:
    loaded = _Loaded()
    for path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            loaded.problems.append(f"{path.name}: cannot read YAML: {exc}")
            continue
        try:
            loaded.files[path.stem] = CrosswalkFile.model_validate(data)
        except ValidationError as exc:
            loaded.problems.extend(f"{path.name}: {m}" for m in _format_validation_error(exc))
    return loaded


def validate_crosswalk(
    directory: Path | None = None,
    owasp: OwaspCatalog | None = None,
    check_risks: Mapping[str, tuple[str, ...]] | None = None,
    lookup: Lookup = catalogs.lookup,
) -> list[str]:
    """Apply every rule in BUILD_SPEC 6.3 (docs/build-log/BUILD_SPEC.md).

    Returns a sorted list of problems (empty when valid).
    """
    directory = directory or crosswalk_dir()
    owasp = owasp or load_owasp_catalog()
    check_risks = check_risk_index() if check_risks is None else check_risks
    risk_ids = {risk.short_id for risk in owasp.risks}

    loaded = _load_files(directory)  # rule 1: schema, unknown keys are errors
    problems = list(loaded.problems)
    referenced_checks: set[str] = set()

    # Rule 2: exactly one file per OWASP risk; risk_id matches the filename.
    for stem, crosswalk_file in loaded.files.items():
        if crosswalk_file.risk_id != stem:
            problems.append(
                f"{stem}.yaml: risk_id {crosswalk_file.risk_id!r} does not match filename"
            )
        if stem not in risk_ids:
            problems.append(f"{stem}.yaml: {stem!r} is not a risk in the OWASP catalog")
    for risk_id in sorted(risk_ids):
        stem_path = directory / f"{risk_id}.yaml"
        if not stem_path.exists():
            problems.append(f"{risk_id}.yaml: missing crosswalk file for OWASP risk {risk_id}")

    for stem, crosswalk_file in sorted(loaded.files.items()):
        name = f"{stem}.yaml"
        if crosswalk_file.catalog_version != owasp.version:
            problems.append(
                f"{name}: catalog_version {crosswalk_file.catalog_version!r} "
                f"does not match OWASP catalog version {owasp.version!r}"
            )
        seen: set[tuple[str, str]] = set()
        counts = {"nist-800-53r5": 0, "nist-csf-2.0": 0}
        for index, mapping in enumerate(crosswalk_file.mappings):
            where = f"{name}: mappings[{index}] {mapping.framework} {mapping.control_id}"
            counts[mapping.framework] += 1

            # Rule 3: control exists in the vendored catalog and is not withdrawn.
            entry = lookup(mapping.framework, mapping.control_id)
            if entry is None:
                problems.append(f"{where}: control ID not found in the vendored catalog")
            elif entry.withdrawn:
                problems.append(f"{where}: control is withdrawn in the vendored catalog")
            elif entry.id != mapping.control_id:
                problems.append(f"{where}: use the display form {entry.id!r}")

            # Rule 5: no duplicate (framework, control_id) within a risk.
            key_id = catalogs.normalize_id(mapping.framework, mapping.control_id)
            key = (mapping.framework, key_id or mapping.control_id)
            if key in seen:
                problems.append(f"{where}: duplicate mapping within this risk")
            seen.add(key)

            # Rule 6: check references exist and the check lists this risk.
            for check_id in mapping.check_ids:
                referenced_checks.add(check_id)
                if check_id not in check_risks:
                    problems.append(f"{where}: check {check_id!r} is not a registered check")
                elif crosswalk_file.risk_id not in check_risks[check_id]:
                    problems.append(
                        f"{where}: check {check_id!r} does not list risk "
                        f"{crosswalk_file.risk_id} in its risk_ids"
                    )

            # Rule 8: rationale length.
            length = len(mapping.rationale.strip())
            if not RATIONALE_MIN <= length <= RATIONALE_MAX:
                problems.append(
                    f"{where}: rationale is {length} characters "
                    f"(must be {RATIONALE_MIN} to {RATIONALE_MAX})"
                )

        # Rule 4: minimum mapping counts per framework.
        if counts["nist-800-53r5"] < MIN_800_53:
            problems.append(
                f"{name}: has {counts['nist-800-53r5']} nist-800-53r5 mappings "
                f"(at least {MIN_800_53} required)"
            )
        if counts["nist-csf-2.0"] < MIN_CSF:
            problems.append(
                f"{name}: has {counts['nist-csf-2.0']} nist-csf-2.0 mappings "
                f"(at least {MIN_CSF} required)"
            )

    # Check risk IDs must exist in the selected OWASP catalog version.
    for check_id, check_risk_ids in sorted(check_risks.items()):
        for risk_id in check_risk_ids:
            if risk_id not in risk_ids:
                problems.append(
                    f"check {check_id}: risk {risk_id} is not in OWASP catalog {owasp.version}"
                )

    # Rule 7: every registered check is referenced by at least one mapping.
    for check_id in sorted(set(check_risks) - referenced_checks):
        problems.append(f"check {check_id}: not referenced by any crosswalk mapping")

    return sorted(problems)


def load_crosswalk(directory: Path | None = None) -> dict[str, CrosswalkFile]:
    """Load all crosswalk files, keyed by risk ID. Raises CrosswalkError if any file is invalid."""
    loaded = _load_files(directory or crosswalk_dir())
    if loaded.problems:
        raise CrosswalkError(loaded.problems)
    return {cw.risk_id: cw for cw in loaded.files.values()}


def load_version_crosswalk(catalog_version: str | None = None) -> dict[str, CrosswalkFile]:
    """Load the crosswalk authored for a catalog version (default from ``versions.yaml``)."""
    resolved = versions.resolve(catalog_version)
    if resolved.crosswalk_dir is None:
        raise versions.VersionError(
            f"no crosswalk has been authored for OWASP catalog version {resolved.id}; "
            "see `mcpxw crosswalk migrate`"
        )
    return load_crosswalk(resolved.crosswalk_dir)


# --- Export ---------------------------------------------------------------------------------


def _rows(
    crosswalk: Mapping[str, CrosswalkFile],
    owasp: OwaspCatalog,
    lookup: Lookup,
) -> list[dict[str, Any]]:
    risks = owasp.by_short_id()
    rows: list[dict[str, Any]] = []
    for risk_id in sorted(crosswalk):
        risk = risks.get(risk_id)
        for mapping in crosswalk[risk_id].mappings:
            entry = lookup(mapping.framework, mapping.control_id)
            rows.append(
                {
                    "risk_id": risk_id,
                    "risk_title": risk.title if risk else "",
                    "framework": mapping.framework,
                    "control_id": mapping.control_id,
                    "control_title": entry.title if entry else "",
                    "relationship": mapping.relationship,
                    "confidence": mapping.confidence,
                    "check_ids": sorted(mapping.check_ids),
                    "rationale": " ".join(mapping.rationale.split()),
                    "review_status": crosswalk[risk_id].review_status,
                    # Derived (computed from vendored NIST files), not authored mapping data.
                    "baselines": federal.baselines_for(mapping.framework, mapping.control_id),
                    "sp800_171r3_derived": federal.sp800_171r3_for(
                        mapping.framework, mapping.control_id
                    ),
                }
            )
    return rows


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _review_status_line(crosswalk: Mapping[str, CrosswalkFile]) -> str:
    draft = sorted(risk_id for risk_id, f in crosswalk.items() if f.review_status == "draft")
    if not draft:
        return "all risk files are `reviewed` by the maintainer"
    if len(draft) == len(crosswalk):
        return "all risk files are `draft`"
    return f"`draft`: {', '.join(draft)}; all other risk files are `reviewed`"


def export_markdown(
    crosswalk: Mapping[str, CrosswalkFile],
    owasp: OwaspCatalog,
    check_risks: Mapping[str, tuple[str, ...]] | None = None,
    lookup: Lookup = catalogs.lookup,
) -> str:
    check_risks = check_risk_index() if check_risks is None else check_risks
    rows = _rows(crosswalk, owasp, lookup)
    risks = owasp.by_short_id()
    n53 = sum(1 for r in rows if r["framework"] == "nist-800-53r5")
    ncsf = len(rows) - n53
    lines = [
        "# OWASP MCP Top 10 to NIST crosswalk",
        "",
        "<!-- GENERATED by `mcpxw crosswalk export --format md`. Do not hand-edit. -->",
        "",
        f"> {DISCLAIMER}",
        "",
        f"- OWASP MCP Top 10 version: `{owasp.version}` (retrieved {owasp.retrieved})",
        f"- Frameworks: {FRAMEWORK_NAMES['nist-800-53r5']}, {FRAMEWORK_NAMES['nist-csf-2.0']}",
        f"- Mappings: {len(rows)} total ({n53} SP 800-53, {ncsf} CSF 2.0)",
        f"- Review status: {_review_status_line(crosswalk)}",
        "- Relationship direction: NIST OLIR convention, the OWASP MCP risk (focal) relative to "
        "the control (reference) (see `docs/methodology.md`)",
        "",
        "Risk IDs and titles are from the OWASP MCP Top 10 (CC BY-NC-SA 4.0), used for reference "
        "with attribution. Summaries and rationales are original to this project (CC BY 4.0).",
        "",
        "**Derived columns (SP 800-53 rows only).** *Baselines* lists the SP 800-53 Rev 5 "
        "baselines (LOW, MODERATE, HIGH, PRIVACY) whose NIST resolved-profile catalogs include the "
        f"control. *{federal.SP800_171R3_LABEL}* lists SP 800-171 Rev 3 requirements whose NIST "
        "source-control references name exactly that control. Both are computed from vendored "
        "NIST OSCAL files, are not authored mappings, and do not count toward the mapping totals. "
        f"{federal.CMMC_NOTE}",
        "",
    ]
    for risk_id in sorted(crosswalk):
        risk = risks.get(risk_id)
        title = risk.title if risk else ""
        risk_checks = sorted(c for c, rs in check_risks.items() if risk_id in rs)
        lines += [f"## {risk_id}: {title}", ""]
        if risk:
            lines += [" ".join(risk.summary.split()), ""]
        coverage = (
            f"Scanner checks: {', '.join(risk_checks)}"
            if risk_checks
            else "Scanner checks: none (not assessed statically; requires active analysis)"
        )
        lines += [
            coverage,
            "",
            "| Framework | Control | Title | Relationship | Confidence | Checks | Rationale "
            "| Baselines | 800-171r3 (derived) |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for row in (r for r in rows if r["risk_id"] == risk_id):
            is_800_53 = row["framework"] == "nist-800-53r5"
            lines.append(
                "| "
                + " | ".join(
                    [
                        "800-53" if row["framework"] == "nist-800-53r5" else "CSF 2.0",
                        row["control_id"],
                        _md_cell(row["control_title"]),
                        row["relationship"],
                        row["confidence"],
                        ", ".join(row["check_ids"]) or "-",
                        _md_cell(row["rationale"]),
                        (", ".join(row["baselines"]) or "none") if is_800_53 else "-",
                        (", ".join(row["sp800_171r3_derived"]) or "none") if is_800_53 else "-",
                    ]
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines)


CSV_FIELDS = [
    "risk_id",
    "risk_title",
    "framework",
    "control_id",
    "control_title",
    "relationship",
    "confidence",
    "check_ids",
    "rationale",
    "review_status",
    "baselines",
    "sp800_171r3_derived",
]


def export_csv(
    crosswalk: Mapping[str, CrosswalkFile],
    owasp: OwaspCatalog,
    lookup: Lookup = catalogs.lookup,
) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in _rows(crosswalk, owasp, lookup):
        writer.writerow(
            safe_row(
                {
                    **row,
                    "check_ids": " ".join(row["check_ids"]),
                    "baselines": " ".join(row["baselines"]),
                    "sp800_171r3_derived": " ".join(row["sp800_171r3_derived"]),
                }
            )
        )
    return buffer.getvalue()


def export_json(
    crosswalk: Mapping[str, CrosswalkFile],
    owasp: OwaspCatalog,
    lookup: Lookup = catalogs.lookup,
) -> str:
    document = {
        "owasp_version": owasp.version,
        "disclaimer": DISCLAIMER,
        "derived_fields_note": (
            "baselines and sp800_171r3_derived are derived from vendored NIST OSCAL files "
            f"({federal.SP800_171R3_LABEL}); they are not authored mappings and are not "
            f"counted in the mapping total. {federal.CMMC_NOTE}"
        ),
        "mappings": _rows(crosswalk, owasp, lookup),
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"
