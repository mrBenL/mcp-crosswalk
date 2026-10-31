"""POA&M-style CSV export and CSV formula-injection protection (V02 N4)."""

import csv
import io
import shutil
from pathlib import Path

import pytest
import yaml
from conftest import materialize
from typer.testing import CliRunner

from mcp_crosswalk import crosswalk as cw
from mcp_crosswalk.cli import app
from mcp_crosswalk.csvsafe import FORMULA_PREFIXES, safe_cell
from mcp_crosswalk.engine import ScanTarget, scan
from mcp_crosswalk.models import DISCLAIMER, SEVERITY_ORDER, Report
from mcp_crosswalk.reporters import poam
from mcp_crosswalk.resources import crosswalk_dir

runner = CliRunner()
GOLDEN = Path(__file__).parent / "golden" / "kitchen_sink.poam.csv"
EXPECTED_COLUMNS = [
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


def _rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text, newline="")))


@pytest.fixture
def ks_report(tmp_path: Path) -> Report:
    return scan([ScanTarget(materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json"))])


def test_columns_and_order(ks_report: Report) -> None:
    text = poam.render(ks_report)
    header = next(csv.reader(io.StringIO(text, newline="")))
    assert header == EXPECTED_COLUMNS == poam.COLUMNS
    assert text.endswith("\r\n")
    assert "\r\n" in text.split("POA&M ID", 1)[1][:400]


def test_one_row_per_finding_with_expected_values(ks_report: Report) -> None:
    rows = _rows(poam.render(ks_report))
    assert len(rows) == len(ks_report.findings) > 0
    by_id = {f.id: f for f in ks_report.findings}
    assert set(by_id) == {r["POA&M ID"] for r in rows}
    for row in rows:
        finding = by_id[row["POA&M ID"]]
        assert row["Weakness Name"] == finding.title
        assert row["Weakness Description"] == f"{finding.evidence.rstrip('.')}. {DISCLAIMER}"
        assert ".. " not in row["Weakness Description"]
        assert row["Source"] == f"mcpxw {ks_report.tool.version} {finding.check_id}"
        assert row["Asset"] == finding.server
        assert row["Client"] == finding.client
        assert row["Config File"] == finding.source_path
        assert row["Severity"] == finding.severity
        assert row["Status"] == "Open"
        assert row["Date Identified"] == ks_report.generated_at[:10]
        assert len(row["Date Identified"]) == 10
        assert row["Scheduled Completion Date"] == row["Milestones"] == row["Comments"] == ""
        assert row["Recommended Remediation"] == finding.remediation
        for risk in finding.risk_ids:
            assert risk in row["OWASP MCP Risk"]
        ids_53 = {c.control_id for c in finding.controls if c.framework == "nist-800-53r5"}
        assert set(filter(None, row["Related 800-53 Controls"].split("; "))) == ids_53
        ids_csf = {c.control_id for c in finding.controls if c.framework == "nist-csf-2.0"}
        assert set(filter(None, row["Related CSF 2.0 Subcategories"].split("; "))) == ids_csf
    secret = next(r for r in rows if r["Weakness Name"].startswith("Literal secret in server env"))
    assert "IA-5: LOW, MODERATE, HIGH" in secret["800-53 Baselines"]
    assert "IA-5(7): none" in secret["800-53 Baselines"]


def test_rows_ordered_by_severity_then_id(ks_report: Report) -> None:
    rows = _rows(poam.render(ks_report))
    keys = [(-SEVERITY_ORDER[r["Severity"]], r["POA&M ID"]) for r in rows]
    assert keys == sorted(keys)
    assert {r["Severity"] for r in rows} == {"high", "medium", "low"}


def test_empty_report_has_header_only(tmp_path: Path) -> None:
    report = scan([ScanTarget(materialize("generic.json", tmp_path / "g.json"))])
    clean = report.model_copy(update={"findings": []})
    assert poam.render(clean) == ",".join(EXPECTED_COLUMNS) + "\r\n"


# --- CSV injection ----------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"])
def test_safe_cell_prefixes_formula_starts(value: str) -> None:
    assert safe_cell(value) == "'" + value


@pytest.mark.parametrize("value", ["plain", "a=b", " =x", "", "'already"])
def test_safe_cell_leaves_other_values(value: str) -> None:
    assert safe_cell(value) == value
    assert safe_cell(None) == ""


def test_poam_neutralizes_hostile_server_names(tmp_path: Path) -> None:
    report = scan([ScanTarget(materialize("csv_injection.json", tmp_path / "inj.json"))])
    rows = _rows(poam.render(report))
    assets = {r["Asset"] for r in rows}
    assert '\'=HYPERLINK("http://x","y")' in assets
    assert {"'+SUM(1,2)", "'-2+3", "'@SUM(A1)", "'\tTAB", "'\rCR"} <= assets
    assert 'plain, "quoted"\nmultiline' in assets  # RFC 4180 quoting round-trips it
    for row in rows:
        for column, cell in row.items():
            assert not cell.startswith(FORMULA_PREFIXES), (column, cell)


def test_crosswalk_csv_export_neutralizes_formulas(tmp_path: Path) -> None:
    target = tmp_path / "crosswalk"
    shutil.copytree(crosswalk_dir(), target)
    path = target / "MCP01.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["mappings"][0]["rationale"] = '=HYPERLINK("http://x","y") for MCP config files'
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    text = cw.export_csv(cw.load_crosswalk(target), cw.load_owasp_catalog())
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["rationale"] == "'" + '=HYPERLINK("http://x","y") for MCP config files'
    for row in rows:
        for cell in row.values():
            assert not cell.startswith(FORMULA_PREFIXES)


# --- CLI and golden ---------------------------------------------------------------------------


def test_cli_writes_poam_file(tmp_path: Path) -> None:
    config = materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json")
    out = tmp_path / "o"
    args = ["scan", "--config", str(config), "--format", "poam", "--out", str(out)]
    result = runner.invoke(app, args)
    assert result.exit_code == 1  # high findings present
    assert sorted(p.name for p in out.iterdir()) == ["mcpxw-poam.csv"]
    assert (out / "mcpxw-poam.csv").read_bytes().decode("utf-8").startswith("POA&M ID,")


def _normalize(text: str, tmp: Path) -> list[list[str]]:
    """Normalize date, finding IDs, version, and temp paths; sort rows for a stable comparison.

    Finding IDs hash the absolute path (see test_cli_scan.normalize), so the severity-then-ID row
    order varies with the temp directory; that order is asserted in
    test_rows_ordered_by_severity_then_id instead.
    """
    rows = list(csv.reader(io.StringIO(text, newline="")))
    header, body = rows[0], rows[1:]
    normalized = []
    for row in body:
        cells = dict(zip(header, row, strict=True))
        cells["POA&M ID"] = "<FINDING_ID>"
        cells["Date Identified"] = "<DATE>"
        cells["Source"] = (
            cells["Source"].split(" ", 2)[0] + " <VERSION> " + cells["Source"].split()[-1]
        )
        cells = {k: v.replace(str(tmp), "<TMP>") for k, v in cells.items()}
        normalized.append([cells[c] for c in header])
    return [header, *sorted(normalized)]


def test_golden_poam(tmp_path: Path, update_golden: bool) -> None:
    report = scan([ScanTarget(materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json"))])
    actual = _normalize(poam.render(report), tmp_path)
    if update_golden:
        buffer = io.StringIO()
        csv.writer(buffer, lineterminator="\n").writerows(actual)
        GOLDEN.write_text(buffer.getvalue(), encoding="utf-8")
    expected = list(csv.reader(io.StringIO(GOLDEN.read_text(encoding="utf-8"), newline="")))
    assert actual == expected
