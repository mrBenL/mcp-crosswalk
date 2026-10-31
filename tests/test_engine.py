from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import FIXTURES, materialize

from mcp_crosswalk.checks.registry import get_registry
from mcp_crosswalk.crosswalk import load_crosswalk
from mcp_crosswalk.engine import (
    ASSESSED,
    NO_ALLOWLIST,
    NOT_ASSESSED,
    AllowlistError,
    ScanTarget,
    load_allowlist,
    scan,
)
from mcp_crosswalk.models import DISCLAIMER

NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def kitchen_sink(tmp_path: Path) -> Path:
    return materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json")


@pytest.fixture
def allowlist_path() -> Path:
    return FIXTURES / "allowlist.yaml"


def test_kitchen_sink_triggers_every_check(kitchen_sink: Path, allowlist_path: Path) -> None:
    report = scan([ScanTarget(kitchen_sink)], allowlist=load_allowlist(allowlist_path), now=NOW)
    triggered = {f.check_id for f in report.findings}
    assert triggered == set(get_registry())


def test_report_shape(kitchen_sink: Path) -> None:
    report = scan([ScanTarget(kitchen_sink)], now=NOW)
    assert report.schema_version == "1.1"
    assert report.tool.name == "mcp-crosswalk"
    assert report.generated_at == "2026-10-07T12:00:00Z"
    assert report.disclaimer == DISCLAIMER
    assert report.catalog.owasp_version == "2025-beta"
    assert [f.id for f in report.catalog.frameworks] == ["nist-800-53r5", "nist-csf-2.0"]
    assert report.inputs[0].status == "ok"
    assert report.summary.total_servers == 11
    assert report.summary.total_findings == len(report.findings)
    assert sum(report.summary.by_severity.values()) == len(report.findings)


def test_findings_are_sorted_by_severity(kitchen_sink: Path) -> None:
    report = scan([ScanTarget(kitchen_sink)], now=NOW)
    order = {"high": 0, "medium": 1, "low": 2}
    ranks = [order[f.severity] for f in report.findings]
    assert ranks == sorted(ranks)


def test_controls_restricted_to_mappings_citing_the_check(kitchen_sink: Path) -> None:
    report = scan([ScanTarget(kitchen_sink)], now=NOW)
    crosswalk = load_crosswalk()
    for finding in report.findings:
        assert finding.controls, finding.check_id
        for control in finding.controls:
            assert control.risk_id in finding.risk_ids
            mapping = next(
                m
                for m in crosswalk[control.risk_id].mappings
                if m.framework == control.framework and m.control_id == control.control_id
            )
            assert finding.check_id in mapping.check_ids
            assert mapping.relationship == control.relationship
            assert control.title
    secrets = next(f for f in report.findings if f.check_id == "MCPXW-001")
    ids = {c.control_id for c in secrets.controls}
    assert {"IA-5(7)", "PR.AA-01"} <= ids
    assert "AC-3" not in ids  # mapped to MCP01 without check evidence


def test_coverage_without_allowlist(kitchen_sink: Path) -> None:
    report = scan([ScanTarget(kitchen_sink)], now=NOW)
    status = {row.risk_id: row.status for row in report.coverage}
    assert status["MCP03"] == NOT_ASSESSED
    assert status["MCP06"] == NOT_ASSESSED
    assert status["MCP08"] == NOT_ASSESSED
    assert status["MCP09"] == NO_ALLOWLIST
    for risk in ("MCP01", "MCP02", "MCP04", "MCP05", "MCP07", "MCP10"):
        assert status[risk] == ASSESSED
    assert not any(f.check_id == "MCPXW-009" for f in report.findings)
    assert [row.risk_id for row in report.coverage] == [f"MCP{n:02d}" for n in range(1, 11)]


def test_coverage_with_allowlist(kitchen_sink: Path, allowlist_path: Path) -> None:
    report = scan([ScanTarget(kitchen_sink)], allowlist=load_allowlist(allowlist_path), now=NOW)
    row = next(r for r in report.coverage if r.risk_id == "MCP09")
    assert row.status == ASSESSED
    assert row.check_ids == ["MCPXW-009"]
    assert row.findings == sum(1 for f in report.findings if f.check_id == "MCPXW-009")


def test_servers_in_report_are_redacted(kitchen_sink: Path, fake_secrets: dict[str, str]) -> None:
    report = scan([ScanTarget(kitchen_sink)], now=NOW)
    dumped = report.model_dump_json()
    for value in fake_secrets.values():
        assert value not in dumped


def test_malformed_and_missing_inputs_recorded(tmp_path: Path) -> None:
    bad = materialize("malformed.json", tmp_path / "bad.json")
    good = materialize("generic.json", tmp_path / "good.json")
    report = scan(
        [ScanTarget(bad), ScanTarget(good), ScanTarget(tmp_path / "missing.json")], now=NOW
    )
    statuses = {Path(i.path).name: i.status for i in report.inputs}
    assert statuses == {"bad.json": "parse_error", "good.json": "ok", "missing.json": "read_error"}
    assert report.summary.total_servers == 1


def test_duplicate_targets_scanned_once(tmp_path: Path) -> None:
    good = materialize("generic.json", tmp_path / "good.json")
    report = scan([ScanTarget(good), ScanTarget(good)], now=NOW)
    assert len(report.inputs) == 1


def test_clean_fixtures_have_no_findings(tmp_path: Path) -> None:
    targets = [
        ScanTarget(
            materialize("claude_desktop.json", tmp_path / "a" / "claude_desktop_config.json")
        ),
        ScanTarget(materialize("claude_code_project.json", tmp_path / "b" / ".mcp.json")),
        ScanTarget(materialize("claude_code_user.json", tmp_path / "c" / ".claude.json")),
        ScanTarget(materialize("cursor.json", tmp_path / "d" / ".cursor" / "mcp.json")),
        ScanTarget(materialize("vscode_project.jsonc", tmp_path / "e" / ".vscode" / "mcp.json")),
        ScanTarget(materialize("windsurf.json", tmp_path / "f" / "mcp_config.json")),
        ScanTarget(materialize("generic.json", tmp_path / "g" / "generic.json")),
    ]
    report = scan(targets, now=NOW)
    assert all(i.status == "ok" for i in report.inputs)
    assert report.findings == []
    assert report.summary.total_servers == 14


def test_scan_is_deterministic(kitchen_sink: Path) -> None:
    first = scan([ScanTarget(kitchen_sink)], now=NOW).model_dump_json()
    second = scan([ScanTarget(kitchen_sink)], now=NOW).model_dump_json()
    assert first == second


def test_load_allowlist_errors(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("key: value\n", encoding="utf-8")
    with pytest.raises(AllowlistError, match="YAML list"):
        load_allowlist(bad)
    with pytest.raises(AllowlistError, match="cannot read"):
        load_allowlist(tmp_path / "missing.yaml")
    broken = tmp_path / "broken.yaml"
    broken.write_text("- [unclosed\n", encoding="utf-8")
    with pytest.raises(AllowlistError):
        load_allowlist(broken)


def test_load_allowlist_normalizes(tmp_path: Path) -> None:
    path = tmp_path / "a.yaml"
    path.write_text("- ' b '\n- a\n- a\n- ''\n", encoding="utf-8")
    assert load_allowlist(path).entries == ("a", "b")
