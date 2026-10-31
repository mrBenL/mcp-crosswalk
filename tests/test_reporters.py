import json
import re
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from conftest import FIXTURES, materialize

from mcp_crosswalk.checks.registry import ALL_CHECKS
from mcp_crosswalk.engine import ScanTarget, load_allowlist, scan
from mcp_crosswalk.models import DISCLAIMER, Report
from mcp_crosswalk.reporters import (
    FORMATS,
    REPORT_FORMATS,
    OutputError,
    html,
    json_reporter,
    markdown,
    parse_formats,
    sarif,
    write_reports,
)
from mcp_crosswalk.schemas import render_schemas

NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)
SCHEMAS = Path(__file__).parent / "schemas"


@pytest.fixture
def ks_report(tmp_path: Path) -> Report:
    path = materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json")
    return scan([ScanTarget(path)], allowlist=load_allowlist(FIXTURES / "allowlist.yaml"), now=NOW)


@pytest.fixture
def hostile_report(tmp_path: Path) -> Report:
    path = materialize("hostile.json", tmp_path / "hostile.json")
    bad = materialize("malformed.json", tmp_path / "malformed.json")
    return scan([ScanTarget(path), ScanTarget(bad)], now=NOW)


@pytest.fixture
def user_file_report(tmp_path: Path) -> Report:
    path = materialize("claude_code_user.json", tmp_path / ".claude.json")
    ks = materialize("kitchen_sink.json", tmp_path / "ks.json")
    return scan([ScanTarget(path), ScanTarget(ks)], now=NOW)


def _all_outputs(report: Report) -> dict[str, str]:
    return {name: renderer(report) for name, (renderer, _) in FORMATS.items()}


# --- JSON ------------------------------------------------------------------------------------


def test_json_validates_against_exported_schema(ks_report: Report, hostile_report: Report) -> None:
    schema = json.loads(render_schemas()["report.schema.json"])
    for report in (ks_report, hostile_report):
        jsonschema.validate(json.loads(json_reporter.render(report)), schema)


def test_json_round_trips(ks_report: Report) -> None:
    assert Report.model_validate_json(json_reporter.render(ks_report)) == ks_report


def test_json_keys_sorted(ks_report: Report) -> None:
    data = json.loads(json_reporter.render(ks_report))
    assert list(data) == sorted(data)


# --- SARIF -----------------------------------------------------------------------------------


def test_sarif_validates_against_official_schema(ks_report: Report, hostile_report: Report) -> None:
    schema = json.loads((SCHEMAS / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    for report in (ks_report, hostile_report):
        errors = sorted(validator.iter_errors(json.loads(sarif.render(report))), key=str)
        assert errors == []


def test_sarif_structure(ks_report: Report) -> None:
    doc = json.loads(sarif.render(ks_report))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == [c.id for c in ALL_CHECKS]
    secret_rule = rules[0]
    assert "MCP01" in secret_rule["properties"]["tags"]
    assert "IA-5(7)" in secret_rule["properties"]["tags"]
    assert "PR.AA-01" in secret_rule["properties"]["tags"]
    assert DISCLAIMER in secret_rule["help"]["text"]
    assert len(run["results"]) == len(ks_report.findings)
    for result, finding in zip(run["results"], ks_report.findings, strict=True):
        assert result["ruleId"] == finding.check_id
        assert rules[result["ruleIndex"]]["id"] == finding.check_id
        assert result["partialFingerprints"]["mcpxwFindingId/v1"] == finding.id
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].startswith("file://")
        assert loc["region"]["startLine"] >= 1
    assert run["properties"]["disclaimer"] == DISCLAIMER


def test_sarif_region_points_at_server_key(ks_report: Report, tmp_path: Path) -> None:
    doc = json.loads(sarif.render(ks_report))
    lines = (tmp_path / "kitchen_sink.json").read_text(encoding="utf-8").splitlines()
    for result in doc["runs"][0]["results"]:
        line = lines[result["locations"][0]["physicalLocation"]["region"]["startLine"] - 1]
        assert f'"{result["properties"]["server"]}"' in line


def test_sarif_region_for_claude_code_projects(user_file_report: Report, tmp_path: Path) -> None:
    lines = (tmp_path / ".claude.json").read_text(encoding="utf-8").splitlines()
    postgres_line = sarif.find_start_line(
        str(tmp_path / ".claude.json"), "postgres", "/home/alex/app"
    )
    assert postgres_line is not None
    assert '"postgres"' in lines[postgres_line - 1]
    assert sarif.find_start_line(str(tmp_path / ".claude.json"), "x", "/missing") is None


def test_sarif_region_with_repeated_server_names(tmp_path: Path) -> None:
    # Review finding 5: the same server name at top level and under two projects.
    config = tmp_path / ".claude.json"
    config.write_text(
        json.dumps(
            {
                "projects": {
                    "/a": {"mcpServers": {"gh": {"command": "npx", "args": ["gh-mcp"]}}},
                    "/b": {"mcpServers": {"gh": {"command": "npx", "args": ["gh-mcp"]}}},
                },
                "mcpServers": {"gh": {"command": "npx", "args": ["gh-mcp"]}},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    lines = config.read_text(encoding="utf-8").splitlines()
    report = scan([ScanTarget(config)], now=NOW)
    doc = json.loads(sarif.render(report))
    starts = {}
    for result, finding in zip(doc["runs"][0]["results"], report.findings, strict=True):
        line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
        starts[finding.project] = line
        assert '"gh"' in lines[line - 1]
    assert len(set(starts.values())) == 3
    assert starts[None] > starts["/b"] > starts["/a"]


def test_sarif_region_omitted_when_not_found(tmp_path: Path) -> None:
    assert sarif.find_start_line(str(tmp_path / "missing.json"), "srv", None) is None


def test_sarif_artifact_uri() -> None:
    assert sarif.artifact_uri("/a b/c.json") == "file:///a%20b/c.json"
    assert sarif.artifact_uri("rel/c d.json") == "rel/c%20d.json"
    assert sarif.artifact_uri("C:\\Users\\x\\mcp.json") == "file:///C:/Users/x/mcp.json"


# --- HTML ------------------------------------------------------------------------------------


def test_html_is_self_contained(ks_report: Report, hostile_report: Report) -> None:
    for report in (ks_report, hostile_report):
        page = html.render(report)
        assert "<script" not in page.lower()
        assert not re.search(r"""(?i)(src|href|action)\s*=\s*["']?\s*(https?:)?//""", page)
        assert not re.search(r"(?i)url\s*\(", page)
        assert "@import" not in page
        assert "<link" not in page.lower()
        assert "<img" not in page.lower()
        assert "<iframe" not in page.lower()
        assert "Content-Security-Policy" in page


def test_html_escapes_hostile_values(hostile_report: Report) -> None:
    page = html.render(hostile_report)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;img src=x onerror=alert(2)&gt;" in page
    assert "<style>body" not in page
    assert "evil&amp;amp;&#34;quote&#39;" in page
    assert "onerror=alert" not in page.replace("&lt;img src=x onerror=alert(2)&gt;", "")


def test_html_severity_is_text_not_color_only(ks_report: Report) -> None:
    page = html.render(ks_report)
    for word in ("HIGH", "MEDIUM", "LOW"):
        assert f">{word}</span>" in page


def test_html_no_findings_message(tmp_path: Path) -> None:
    path = materialize("generic.json", tmp_path / "g.json")
    page = html.render(scan([ScanTarget(path)], now=NOW))
    assert "No findings for the risks that were assessed statically." in page


# --- Markdown --------------------------------------------------------------------------------


def test_markdown_sections(ks_report: Report) -> None:
    text = markdown.render(ks_report)
    for heading in (
        "# MCP configuration scan report",
        "## Summary",
        "## Coverage matrix",
        "## Findings",
        "### Severity: HIGH",
        "## Server inventory",
    ):
        assert heading in text
    assert "Not assessed (requires active analysis)" in text
    assert "SP 800-53r5 IA-5(7) Authenticator Management" in text


def test_markdown_escapes_hostile_values(hostile_report: Report) -> None:
    text = markdown.render(hostile_report)
    assert "<script>" not in text
    assert "<img" not in text
    assert "&lt;script&gt;" in text
    assert "](javascript" not in text
    for row in (line for line in text.splitlines() if line.startswith("| ")):
        assert row.count(" | ") == row.count("|") - 2 - row.count("\\|")


def test_bidi_controls_are_neutralized(hostile_report: Report) -> None:
    for text in (markdown.render(hostile_report), html.render(hostile_report)):
        assert "\u202e" not in text
        assert "U+202E" in text


def test_neutralize() -> None:
    from mcp_crosswalk.reporters.common import neutralize

    assert neutralize("a\u202eb\x1bc\td") == "a<U+202E>b<U+001B>c\td"
    assert neutralize("café") == "café"


def test_markdown_trusted_text_is_lightly_escaped(ks_report: Report) -> None:
    text = markdown.render(ks_report)
    assert "Authenticator Management \\| No Embedded" in text
    assert "intersects_with" in text
    assert "(\\~/.ssh" in text


def test_markdown_no_findings(tmp_path: Path) -> None:
    path = materialize("generic.json", tmp_path / "g.json")
    text = markdown.render(scan([ScanTarget(path)], now=NOW))
    assert "No findings for the risks that were assessed statically." in text


def test_markdown_shows_project(user_file_report: Report) -> None:
    assert "postgres [/home/alex/app]" in markdown.render(user_file_report)


# --- Cross-format guarantees -----------------------------------------------------------------


def test_every_format_includes_disclaimer(ks_report: Report, hostile_report: Report) -> None:
    for report in (ks_report, hostile_report):
        for name, text in _all_outputs(report).items():
            assert DISCLAIMER in text, name


def test_no_format_makes_compliance_claims(ks_report: Report) -> None:
    banned = re.compile(r"(?i)\b(compliant|non-compliant|noncompliant|pass|passed|fail|failed)\b")
    for name, text in _all_outputs(ks_report).items():
        assert not banned.search(text), f"{name}: {banned.search(text)}"


def test_every_format_shows_not_assessed_risks(ks_report: Report) -> None:
    # The POA&M CSV is one row per finding by design; the coverage matrix lives in the report
    # formats written alongside it (DECISIONS D42).
    outputs = _all_outputs(ks_report)
    assert set(outputs) - set(REPORT_FORMATS) == {"poam"}
    for name in REPORT_FORMATS:
        text = outputs[name]
        for risk in ("MCP03", "MCP06", "MCP08"):
            assert risk in text, (name, risk)
        assert "Not assessed (requires active analysis)" in text, name


# --- Writer ----------------------------------------------------------------------------------


def test_parse_formats() -> None:
    assert parse_formats("sarif, json") == ["json", "sarif"]
    assert parse_formats("json,md,html,sarif") == list(REPORT_FORMATS)
    assert parse_formats("poam,json,md,html,sarif") == list(FORMATS)
    with pytest.raises(ValueError, match="unknown format"):
        parse_formats("json,pdf")
    with pytest.raises(ValueError):
        parse_formats(" , ")


def test_write_reports(ks_report: Report, tmp_path: Path) -> None:
    out = tmp_path / "out" / "nested"
    written = write_reports(ks_report, list(FORMATS), out)
    assert sorted(p.name for p in written) == sorted(p.name for p in out.iterdir())
    assert len(written) == 5


def test_write_reports_refuses_symlink(ks_report: Report, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    (out / "mcpxw-report.json").symlink_to(victim)
    with pytest.raises(OutputError, match="symlink"):
        write_reports(ks_report, ["json"], out)
    assert victim.read_text(encoding="utf-8") == "keep me"


def test_write_reports_refuses_file_as_dir(ks_report: Report, tmp_path: Path) -> None:
    out = tmp_path / "file"
    out.write_text("x", encoding="utf-8")
    with pytest.raises(OutputError, match="not a directory"):
        write_reports(ks_report, ["json"], out)
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "mcpxw-report.json").mkdir()
    with pytest.raises(OutputError, match="not a regular file"):
        write_reports(ks_report, ["json"], tmp_path / "d")
