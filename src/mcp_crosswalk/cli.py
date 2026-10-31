"""Command-line interface for mcp-crosswalk (`mcpxw`).

Exit codes for ``scan``: 0 = no findings at or above ``--fail-on``; 1 = findings at or above it;
2 = usage or runtime error.
"""

from __future__ import annotations

import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from mcp_crosswalk import __version__, enrich, federal, versions
from mcp_crosswalk import crosswalk as cw
from mcp_crosswalk.checks.base import Allowlist
from mcp_crosswalk.checks.docs import render_checks_markdown
from mcp_crosswalk.checks.registry import ALL_CHECKS
from mcp_crosswalk.discovery.discover import discover_configs
from mcp_crosswalk.engine import AllowlistError, ScanTarget, load_allowlist, scan
from mcp_crosswalk.migrate import migrate_crosswalk
from mcp_crosswalk.models import (
    DISCLAIMER,
    SEVERITY_ORDER,
    CrosswalkFile,
    OwaspCatalog,
    Report,
)
from mcp_crosswalk.reporters import OutputError, parse_formats, write_reports
from mcp_crosswalk.schemas import export_schemas

app = typer.Typer(
    name="mcpxw",
    help="OWASP MCP Top 10 to NIST crosswalk and offline static MCP config scanner.",
    no_args_is_help=True,
    add_completion=False,
    # Never render local variables in tracebacks: they can hold raw config text and secrets.
    pretty_exceptions_enable=False,
    pretty_exceptions_show_locals=False,
)
crosswalk_app = typer.Typer(help="Validate, show, and export the crosswalk.", no_args_is_help=True)
schema_app = typer.Typer(help="Export JSON Schemas.", no_args_is_help=True)
checks_app = typer.Typer(help="Describe the static checks.", no_args_is_help=True)
app.add_typer(crosswalk_app, name="crosswalk")
app.add_typer(schema_app, name="schema")
app.add_typer(checks_app, name="checks")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class ExportFormat(StrEnum):
    md = "md"
    csv = "csv"
    json = "json"


class FrameworkOption(StrEnum):
    sp800_53 = "nist-800-53r5"
    csf = "nist-csf-2.0"


class FailOn(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


class ChecksFormat(StrEnum):
    text = "text"
    md = "md"


def _fail(message: str) -> typer.Exit:
    typer.echo(f"Error: {message}", err=True)
    return typer.Exit(EXIT_ERROR)


CatalogVersionOption = Annotated[
    str | None,
    typer.Option(
        "--catalog-version",
        help="OWASP MCP Top 10 catalog version (default from catalog/owasp-mcp/versions.yaml).",
    ),
]


def _resolve_version(catalog_version: str | None) -> versions.ResolvedVersion:
    """Resolve ``--catalog-version``; unknown versions exit 2 with the available list."""
    try:
        return versions.resolve(catalog_version)
    except versions.VersionError as exc:
        raise _fail(str(exc)) from exc


def _load_for_version(
    catalog_version: str | None,
) -> tuple[dict[str, CrosswalkFile], OwaspCatalog, dict[str, tuple[str, ...]]]:
    resolved = _resolve_version(catalog_version)
    try:
        return (
            cw.load_version_crosswalk(resolved.id),
            versions.load_owasp(resolved.id),
            versions.check_risk_index_for(resolved.id),
        )
    except versions.VersionError as exc:
        raise _fail(str(exc)) from exc


def _write_text(out: Path, text: str) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", newline="\n")
    typer.echo(f"Wrote {out}")


def discovery_roots(project_dir: Path | None) -> tuple[Path, Path, str, Path | None]:
    """Real-environment roots for ``--discover``. Tests replace this function."""
    appdata = os.environ.get("APPDATA")
    return (
        Path.home(),
        project_dir or Path.cwd(),
        sys.platform,
        Path(appdata) if appdata else None,
    )


@app.callback()
def main() -> None:
    """OWASP MCP Top 10 to NIST crosswalk and offline static MCP config scanner."""


@app.command()
def version() -> None:
    """Print the tool version."""
    typer.echo(__version__)


# --- scan ----------------------------------------------------------------------------------


def _summary(report: Report, written: list[Path], threshold: FailOn) -> None:
    s = report.summary
    assessed = [r.risk_id for r in report.coverage if r.status == "Assessed (static)"]
    not_assessed = [r.risk_id for r in report.coverage if r.status != "Assessed (static)"]
    errors = [i for i in report.inputs if i.status != "ok"]
    typer.echo("mcpxw scan summary")
    typer.echo(
        f"  Config files:   {len(report.inputs)} ({len(errors)} could not be read or parsed)"
    )
    typer.echo(f"  Servers:        {s.total_servers}")
    typer.echo(
        f"  Findings:       {s.total_findings} "
        f"(high {s.by_severity.get('high', 0)}, medium {s.by_severity.get('medium', 0)}, "
        f"low {s.by_severity.get('low', 0)})"
    )
    typer.echo(f"  Assessed:       {', '.join(assessed) or '-'}")
    typer.echo(f"  Not assessed:   {', '.join(not_assessed) or '-'}")
    typer.echo(f"  Exit threshold: {threshold.value}")
    for path in written:
        typer.echo(f"  Report:         {path}")
    typer.echo(f"  Note: {report.disclaimer}")


def _exit_code(report: Report, threshold: FailOn) -> int:
    if threshold is FailOn.none:
        return EXIT_OK
    floor = SEVERITY_ORDER[threshold.value]
    hit = any(SEVERITY_ORDER[f.severity] >= floor for f in report.findings)
    return EXIT_FINDINGS if hit else EXIT_OK


@app.command("scan")
def scan_command(
    config: Annotated[
        list[Path] | None,
        typer.Option("--config", help="MCP client config file to scan (repeatable)."),
    ] = None,
    discover: Annotated[
        bool, typer.Option("--discover", help="Scan config files in known client locations.")
    ] = False,
    project_dir: Annotated[
        Path | None,
        typer.Option(help="Project directory for project-scoped configs (default: current)."),
    ] = None,
    allowlist: Annotated[
        Path | None,
        typer.Option(help="YAML list of approved server names, packages, or URL prefixes."),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            help="Comma-separated: json,md,html,sarif,poam (poam writes mcpxw-poam.csv).",
        ),
    ] = "json,md",
    out: Annotated[Path, typer.Option(help="Output directory.")] = Path("mcpxw-report"),
    fail_on: Annotated[
        FailOn, typer.Option(help="Exit 1 if any finding is at or above this severity.")
    ] = FailOn.high,
    catalog_version: CatalogVersionOption = None,
    full_paths: Annotated[
        bool,
        typer.Option(
            "--full-paths",
            help="Show full file paths in reports. By default the home directory is shown as ~.",
        ),
    ] = False,
) -> None:
    """Statically scan MCP client config files and write reports."""
    if not config and not discover:
        raise _fail("give at least one --config PATH or use --discover")
    version_id = _resolve_version(catalog_version).id
    try:
        formats = parse_formats(format)
    except ValueError as exc:
        raise _fail(str(exc)) from exc

    missing = [str(path) for path in config or [] if not path.is_file()]
    if missing:
        raise _fail(f"--config path not found or not a file: {', '.join(missing)}")

    targets = [ScanTarget(path) for path in config or []]
    home = Path.home()
    if discover:
        home, project, platform, appdata = discovery_roots(project_dir)
        found = discover_configs(home, project, platform, appdata)
        targets += [ScanTarget(d.path, d.location.client, d.location.scope) for d in found]
        typer.echo(f"Discovered {len(found)} config file(s).")

    try:
        loaded_allowlist: Allowlist | None = load_allowlist(allowlist) if allowlist else None
        report = scan(targets, allowlist=loaded_allowlist, catalog_version=version_id)
        written = write_reports(report, formats, out, home=None if full_paths else home)
    except (AllowlistError, OutputError, cw.CrosswalkError, versions.VersionError, OSError) as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:
        # Never crash with exit 1 (the "findings" code) or echo config content in a traceback.
        raise _fail(f"unexpected internal error ({type(exc).__name__}); no report written") from exc

    _summary(report, written, fail_on)
    if report.inputs and not any(i.status == "ok" for i in report.inputs):
        typer.echo("Error: no config file could be read or parsed; nothing was assessed.", err=True)
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(_exit_code(report, fail_on))


# --- enrich --------------------------------------------------------------------------------


@app.command("enrich")
def enrich_command(
    input_path: Annotated[
        Path, typer.Argument(metavar="INPUT.sarif", help="SARIF 2.1.0 file from another tool.")
    ],
    out: Annotated[Path, typer.Option(help="Output directory.")] = Path("mcpxw-report"),
    format: Annotated[
        str,
        typer.Option(
            "--format",
            help="Comma-separated: sarif (<stem>.enriched.sarif), json and md (summaries).",
        ),
    ] = "sarif",
    catalog_version: CatalogVersionOption = None,
) -> None:
    """Add crosswalk controls to SARIF results that name OWASP MCP Top 10 risk IDs.

    Exit 0 on success; 2 when the input is not usable SARIF or on any other error. The input is
    only read: no URI in it is fetched and nothing in it is run.
    """
    try:
        formats = enrich.parse_enrich_formats(format)
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    version_id = _resolve_version(catalog_version).id
    try:
        document = enrich.load_sarif(input_path)
        summary = enrich.enrich_document(document, version_id, input_name=input_path.name)
        files: dict[str, str] = {}
        if "sarif" in formats:
            files[enrich.output_name(input_path)] = enrich.render_sarif(document)
        if "json" in formats:
            files[enrich.SUMMARY_JSON] = enrich.render_summary_json(summary)
        if "md" in formats:
            files[enrich.SUMMARY_MD] = enrich.render_summary_markdown(summary)
        written = enrich.write_outputs(out, files, input_path)
    except (enrich.EnrichInputError, versions.VersionError, cw.CrosswalkError, OSError) as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:
        # Never echo input content in a traceback.
        raise _fail(f"unexpected internal error ({type(exc).__name__}); nothing written") from exc
    typer.echo("mcpxw enrich summary")
    typer.echo(f"  Catalog version: {summary.catalog_version}")
    typer.echo(f"  Results:         {summary.total_results} in {summary.runs} run(s)")
    typer.echo(f"  Enriched:        {summary.enriched}")
    typer.echo(
        f"  Not enriched:    {summary.not_enriched} (no OWASP MCP risk ID {summary.no_id}; "
        f"ID without crosswalk {summary.id_without_crosswalk}; "
        f"properties not an object {summary.properties_not_object})"
    )
    for path in written:
        typer.echo(f"  Wrote:           {path}")
    typer.echo(f"  Note: {enrich.ID_SCHEME_NOTE}")
    typer.echo(f"  Note: {DISCLAIMER}")


# --- crosswalk -----------------------------------------------------------------------------


@crosswalk_app.command("validate")
def crosswalk_validate(
    catalog_version: CatalogVersionOption = None,
    crosswalk_dir: Annotated[
        Path | None,
        typer.Option(
            help="Validate this directory instead of the version's crosswalk "
            "(for example the output of `crosswalk migrate`)."
        ),
    ] = None,
) -> None:
    """Validate every crosswalk file against the schema, catalogs, and check registry."""
    resolved = _resolve_version(catalog_version)
    directory = crosswalk_dir or resolved.crosswalk_dir
    if directory is None:
        raise _fail(f"no crosswalk is configured for {resolved.id}; pass --crosswalk-dir")
    if not directory.is_dir():
        raise _fail(f"crosswalk directory {directory} does not exist")
    try:
        owasp = versions.load_owasp(resolved.id)
        check_risks = versions.check_risk_index_for(resolved.id)
    except versions.VersionError as exc:
        raise _fail(str(exc)) from exc
    problems = cw.validate_crosswalk(directory, owasp=owasp, check_risks=check_risks)
    if problems:
        typer.echo(f"Crosswalk INVALID: {len(problems)} problem(s)", err=True)
        for problem in problems:
            typer.echo(f"  - {problem}", err=True)
        raise typer.Exit(EXIT_FINDINGS)
    crosswalk = cw.load_crosswalk(directory)
    total = sum(len(f.mappings) for f in crosswalk.values())
    typer.echo(
        f"Crosswalk valid: {len(crosswalk)} risk files, {total} mappings "
        f"(OWASP catalog {resolved.id})."
    )


@crosswalk_app.command("show")
def crosswalk_show(
    risk: Annotated[str | None, typer.Option(help="Risk ID, for example MCP01.")] = None,
    framework: Annotated[
        FrameworkOption | None, typer.Option(help="Limit to one framework.")
    ] = None,
    catalog_version: CatalogVersionOption = None,
) -> None:
    """Print mappings to the terminal."""
    crosswalk, owasp, _ = _load_for_version(catalog_version)
    titles = {r.short_id: r.title for r in owasp.risks}
    if risk is not None:
        risk = risk.strip().upper()
        if risk not in crosswalk:
            typer.echo(f"Unknown risk {risk!r}. Known: {', '.join(sorted(crosswalk))}", err=True)
            raise typer.Exit(EXIT_ERROR)
    for risk_id in sorted(crosswalk):
        if risk is not None and risk_id != risk:
            continue
        typer.echo(f"{risk_id}: {titles.get(risk_id, '')}")
        for mapping in crosswalk[risk_id].mappings:
            if framework is not None and mapping.framework != framework.value:
                continue
            checks = ",".join(mapping.check_ids) or "-"
            typer.echo(
                f"  {mapping.framework:<14} {mapping.control_id:<10} {mapping.relationship:<16}"
                f" {mapping.confidence:<7} checks={checks}"
            )
            if mapping.framework == "nist-800-53r5":
                baselines = federal.baselines_for(mapping.framework, mapping.control_id)
                derived = federal.sp800_171r3_for(mapping.framework, mapping.control_id)
                typer.echo(
                    f"  {'':<14} baselines: {', '.join(baselines) or 'none'}; "
                    f"{federal.SP800_171R3_LABEL}: {', '.join(derived) or 'none'}"
                )
    typer.echo(f"Derived columns are not authored mappings. {federal.CMMC_NOTE}")


@crosswalk_app.command("export")
def crosswalk_export(
    format: Annotated[ExportFormat, typer.Option("--format", help="Output format.")],
    out: Annotated[Path | None, typer.Option(help="Output file (default: stdout).")] = None,
    catalog_version: CatalogVersionOption = None,
) -> None:
    """Export the crosswalk as Markdown, CSV, or JSON."""
    crosswalk, owasp, check_risks = _load_for_version(catalog_version)
    if format is ExportFormat.md:
        text = cw.export_markdown(crosswalk, owasp, check_risks)
    elif format is ExportFormat.csv:
        text = cw.export_csv(crosswalk, owasp)
    else:
        text = cw.export_json(crosswalk, owasp)
    if out is None:
        typer.echo(text, nl=False)
        return
    _write_text(out, text)


@crosswalk_app.command("migrate")
def crosswalk_migrate(
    to: Annotated[str, typer.Option("--to", help="Target OWASP catalog version.")],
    out: Annotated[
        Path, typer.Option(help="Directory for the migrated copies (never the source).")
    ],
) -> None:
    """Write copies of the crosswalk renumbered for another OWASP catalog version.

    Exit 0 when every risk in the target version has a migrated file; 1 when some new risk has no
    crosswalk file yet (the gap is listed); 2 on errors.
    """
    _resolve_version(to)
    try:
        result = migrate_crosswalk(to, out)
    except (versions.VersionError, cw.CrosswalkError, OSError) as exc:
        raise _fail(str(exc)) from exc
    typer.echo(f"Migrated crosswalk {result.from_version} -> {result.to_version}")
    typer.echo(f"  Unchanged IDs: {', '.join(result.unchanged) or '-'}")
    for old, new in result.renamed:
        typer.echo(f"  Renamed:       {old} -> {new}")
    for old, count, note in result.retired:
        typer.echo(f"  Retired:       {old} ({count} mapping(s) not carried over): {note}")
    for risk_id in result.new_unmapped:
        typer.echo(f"  New, unmapped: {risk_id} (no crosswalk file; author one before adopting)")
    for path in result.written:
        typer.echo(f"  Wrote {path}")
    typer.echo("  Migrated files are review_status: draft; review them against the new risk text.")
    if result.new_unmapped:
        raise typer.Exit(EXIT_FINDINGS)


# --- checks --------------------------------------------------------------------------------


@checks_app.command("list")
def checks_list(
    format: Annotated[
        ChecksFormat, typer.Option("--format", help="text, or md for docs/checks.md.")
    ] = ChecksFormat.text,
    out: Annotated[Path | None, typer.Option(help="Output file (default: stdout).")] = None,
) -> None:
    """List the static checks."""
    if format is ChecksFormat.md:
        text = render_checks_markdown()
    else:
        rows = [f"{'ID':<10} {'Severity':<8} {'Risks':<12} Title"]
        for check in ALL_CHECKS:
            suffix = " (needs --allowlist)" if check.requires_allowlist else ""
            rows.append(
                f"{check.id:<10} {check.severity:<8} {','.join(check.risk_ids):<12} "
                f"{check.title}{suffix}"
            )
        text = "\n".join(rows) + "\n"
    if out is None:
        typer.echo(text, nl=False)
        return
    _write_text(out, text)


# --- schema --------------------------------------------------------------------------------


@schema_app.command("export")
def schema_export(
    out: Annotated[Path, typer.Option(help="Output directory.")] = Path("schema"),
) -> None:
    """Export JSON Schemas for crosswalk files and scan reports."""
    for path in export_schemas(out):
        typer.echo(f"Wrote {path}")
