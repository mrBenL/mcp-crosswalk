import json
from pathlib import Path
from typing import Any

import pytest
from conftest import FIXTURES, materialize
from typer.testing import CliRunner

from mcp_crosswalk import cli
from mcp_crosswalk.cli import app

runner = CliRunner()
GOLDEN = Path(__file__).parent / "golden"

# fixture file -> the real file name it is copied to (client detection depends on the name)
FIXTURE_TARGETS = {
    "claude_desktop.json": "claude_desktop_config.json",
    "claude_code_project.json": ".mcp.json",
    "claude_code_user.json": ".claude.json",
    "cursor.json": ".cursor/mcp.json",
    "vscode_project.jsonc": ".vscode/mcp.json",
    "vscode_settings.jsonc": ".config/Code/User/settings.json",
    "windsurf.json": ".codeium/windsurf/mcp_config.json",
    "generic.json": "generic.json",
    "kitchen_sink.json": "kitchen_sink.json",
    "malformed.json": "malformed.json",
    "hostile.json": "hostile.json",
}


def _place(fixture: str, root: Path) -> Path:
    return materialize(fixture, root / FIXTURE_TARGETS[fixture])


def _scan(args: list[str]) -> Any:
    return runner.invoke(app, ["scan", *args])


def normalize(text: str, tmp: Path) -> dict[str, Any]:
    """Normalize generated_at, tool version, and absolute temp paths for golden comparison.

    Finding IDs hash the absolute source path, so they are path-dependent like the paths
    themselves and are normalized too. ID stability at a fixed path is covered by
    ``test_two_runs_are_identical`` and ``test_finding_ids_match_formula``.
    """
    data = json.loads(text)
    data["generated_at"] = "<GENERATED_AT>"
    data["tool"]["version"] = "<VERSION>"
    for finding in data["findings"]:
        finding["id"] = "<FINDING_ID>"
    dumped = json.dumps(data, sort_keys=True, indent=2)
    dumped = dumped.replace(json.dumps(str(tmp))[1:-1], "<TMP>")
    normalized: dict[str, Any] = json.loads(dumped)
    return normalized


# --- Usage and exit codes --------------------------------------------------------------------


def test_scan_requires_config_or_discover() -> None:
    result = _scan([])
    assert result.exit_code == 2
    assert "--config" in result.output


def test_scan_rejects_unknown_format(tmp_path: Path) -> None:
    path = _place("generic.json", tmp_path)
    result = _scan(["--config", str(path), "--format", "json,pdf", "--out", str(tmp_path / "o")])
    assert result.exit_code == 2
    assert "unknown format" in result.output


def test_scan_bad_fail_on_is_usage_error(tmp_path: Path) -> None:
    path = _place("generic.json", tmp_path)
    assert _scan(["--config", str(path), "--fail-on", "critical"]).exit_code == 2


def test_scan_bad_allowlist_is_runtime_error(tmp_path: Path) -> None:
    path = _place("generic.json", tmp_path)
    bad = tmp_path / "allow.yaml"
    bad.write_text("not: a list\n", encoding="utf-8")
    result = _scan(["--config", str(path), "--allowlist", str(bad), "--out", str(tmp_path / "o")])
    assert result.exit_code == 2
    assert "YAML list" in result.output


def test_missing_config_path_is_usage_error(tmp_path: Path) -> None:
    # Review finding 3: a typo in a CI path must not produce a green build.
    result = _scan(["--config", str(tmp_path / "nope.json"), "--out", str(tmp_path / "o")])
    assert result.exit_code == 2
    assert "not found" in result.output
    assert not (tmp_path / "o").exists()


def test_all_inputs_unparseable_exits_2_but_writes_report(tmp_path: Path) -> None:
    bad = _place("malformed.json", tmp_path)
    out = tmp_path / "o"
    result = _scan(["--config", str(bad), "--out", str(out), "--fail-on", "none"])
    assert result.exit_code == 2
    assert "nothing was assessed" in result.output
    assert (out / "mcpxw-report.json").is_file()


def test_partial_parse_errors_do_not_change_exit_code(tmp_path: Path) -> None:
    bad = _place("malformed.json", tmp_path)
    good = _place("generic.json", tmp_path)
    result = _scan(["--config", str(bad), "--config", str(good), "--out", str(tmp_path / "o")])
    assert result.exit_code == 0


def test_huge_integer_config_is_recorded_not_crash(tmp_path: Path) -> None:
    # Review finding 2: previously a traceback with exit 1.
    big = tmp_path / "big.json"
    big.write_text('{"mcpServers": {"s": {"args": [' + "9" * 5000 + "]}}}", encoding="utf-8")
    good = _place("generic.json", tmp_path)
    out = tmp_path / "o"
    result = _scan(["--config", str(big), "--config", str(good), "--out", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert {i["status"] for i in data["inputs"]} == {"ok", "parse_error"}


def test_unexpected_error_exits_2_without_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("SECRET-CONTENT")

    monkeypatch.setattr(cli, "scan", boom)
    path = _place("generic.json", tmp_path)
    result = _scan(["--config", str(path), "--out", str(tmp_path / "o")])
    assert result.exit_code == 2
    assert "unexpected internal error (RuntimeError)" in result.output
    assert "SECRET-CONTENT" not in result.output


def test_tracebacks_never_show_locals() -> None:
    # Review finding 6.
    assert app.pretty_exceptions_show_locals is False
    assert app.pretty_exceptions_enable is False


def test_same_file_given_twice_with_different_spellings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review finding 11: relative and absolute spellings of one file are scanned once.
    path = _place("kitchen_sink.json", tmp_path)
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "o"
    _scan(["--config", "kitchen_sink.json", "--config", str(path), "--out", str(out)])
    data = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert len(data["inputs"]) == 1


def test_scan_out_is_a_file_is_runtime_error(tmp_path: Path) -> None:
    path = _place("generic.json", tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    result = _scan(["--config", str(path), "--out", str(blocker)])
    assert result.exit_code == 2


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [(None, 1), ("high", 1), ("medium", 1), ("low", 1), ("none", 0)],
)
def test_exit_codes_kitchen_sink(tmp_path: Path, fail_on: str | None, expected: int) -> None:
    path = _place("kitchen_sink.json", tmp_path)
    args = ["--config", str(path), "--out", str(tmp_path / "o")]
    if fail_on:
        args += ["--fail-on", fail_on]
    assert _scan(args).exit_code == expected


def test_exit_code_threshold_respects_severity(tmp_path: Path) -> None:
    # Only a low-severity finding (MCPXW-008): below the default "high" threshold.
    config = tmp_path / "remote.json"
    config.write_text('{"mcpServers": {"r": {"url": "https://r.example.com/mcp"}}}', "utf-8")
    base = ["--config", str(config), "--out", str(tmp_path / "o")]
    assert _scan(base).exit_code == 0
    assert _scan([*base, "--fail-on", "medium"]).exit_code == 0
    assert _scan([*base, "--fail-on", "low"]).exit_code == 1


def test_clean_scan_exits_zero_and_prints_summary(tmp_path: Path) -> None:
    path = _place("generic.json", tmp_path)
    out = tmp_path / "out"
    result = _scan(["--config", str(path), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "Findings:       0" in result.output
    assert "Not assessed:   MCP03, MCP06, MCP08, MCP09" in result.output
    assert sorted(p.name for p in out.iterdir()) == ["mcpxw-report.json", "mcpxw-report.md"]


def test_scan_all_formats(tmp_path: Path) -> None:
    path = _place("kitchen_sink.json", tmp_path)
    out = tmp_path / "out"
    result = _scan(["--config", str(path), "--format", "json,md,html,sarif", "--out", str(out)])
    assert result.exit_code == 1
    names = sorted(p.name for p in out.iterdir())
    assert names == [
        "mcpxw-report.html",
        "mcpxw-report.json",
        "mcpxw-report.md",
        "mcpxw-report.sarif",
    ]


def test_terminal_output_never_shows_secrets(tmp_path: Path, fake_secrets: dict[str, str]) -> None:
    path = _place("kitchen_sink.json", tmp_path)
    result = _scan(["--config", str(path), "--out", str(tmp_path / "o")])
    for value in fake_secrets.values():
        assert value not in result.output


def test_scan_with_allowlist(tmp_path: Path) -> None:
    path = _place("kitchen_sink.json", tmp_path)
    out = tmp_path / "o"
    allow = FIXTURES / "allowlist.yaml"
    result = _scan(["--config", str(path), "--allowlist", str(allow), "--out", str(out)])
    data = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert any(f["check_id"] == "MCPXW-009" for f in data["findings"])
    assert "Not assessed:   MCP03, MCP06, MCP08" in result.output


def test_scan_discover_uses_injected_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, project = tmp_path / "home", tmp_path / "proj"
    materialize("claude_code_user.json", home / ".claude.json")
    materialize("claude_code_project.json", project / ".mcp.json")
    materialize("vscode_project.jsonc", project / ".vscode" / "mcp.json")

    def fake_roots(project_dir: Path | None) -> tuple[Path, Path, str, Path | None]:
        assert project_dir == project
        return home, project, "linux", None

    monkeypatch.setattr(cli, "discovery_roots", fake_roots)
    out = tmp_path / "out"
    result = _scan(["--discover", "--project-dir", str(project), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "Discovered 3 config file(s)." in result.output
    data = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    clients = sorted({(i["client"], Path(i["path"]).name) for i in data["inputs"]})
    assert clients == [
        ("claude_code", ".claude.json"),
        ("claude_code", ".mcp.json"),
        ("vscode", "mcp.json"),
    ]
    scopes = {s["name"]: s["scope"] for s in data["servers"]}
    assert scopes["sentry"] == "project"
    assert scopes["memory"] == "user"


def test_discovery_roots_reads_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Only exercises the root-selection helper; nothing is read from these paths.
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    home, project, platform, appdata = cli.discovery_roots(tmp_path)
    assert project == tmp_path
    assert appdata == tmp_path / "appdata"
    assert platform
    assert home
    monkeypatch.delenv("APPDATA")
    assert cli.discovery_roots(None)[3] is None


def test_checks_list_text_and_md(tmp_path: Path) -> None:
    result = runner.invoke(app, ["checks", "list"])
    assert result.exit_code == 0
    assert "MCPXW-009" in result.stdout
    assert "needs --allowlist" in result.stdout
    out = tmp_path / "checks.md"
    assert (
        runner.invoke(app, ["checks", "list", "--format", "md", "--out", str(out)]).exit_code == 0
    )
    assert out.read_text(encoding="utf-8").startswith("# Static checks")
    md = runner.invoke(app, ["checks", "list", "--format", "md"])
    assert "## MCPXW-001" in md.stdout


def test_committed_checks_doc_is_current() -> None:
    from mcp_crosswalk.checks.docs import render_checks_markdown

    committed = (Path(__file__).resolve().parent.parent / "docs" / "checks.md").read_text("utf-8")
    assert committed == render_checks_markdown()


# --- Golden files and determinism ------------------------------------------------------------


def _check_golden(actual: dict[str, Any], name: str, update: bool) -> None:
    golden_path = GOLDEN / name
    if update:
        golden_path.write_text(
            json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    assert actual == json.loads(golden_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("fixture", sorted(FIXTURE_TARGETS))
def test_golden_reports(tmp_path: Path, fixture: str, update_golden: bool) -> None:
    path = _place(fixture, tmp_path)
    out = tmp_path / "out"
    result = _scan(
        ["--config", str(path), "--format", "json", "--out", str(out), "--fail-on", "none"]
    )
    # A scan in which no input could be parsed still writes its report but exits 2.
    expected_exit = 2 if fixture == "malformed.json" else 0
    assert result.exit_code == expected_exit, result.output
    actual = normalize((out / "mcpxw-report.json").read_text(encoding="utf-8"), tmp_path)
    _check_golden(actual, Path(fixture).stem + ".json", update_golden)


def test_golden_kitchen_sink_with_allowlist(tmp_path: Path, update_golden: bool) -> None:
    path = _place("kitchen_sink.json", tmp_path)
    out = tmp_path / "out"
    args = ["--config", str(path), "--allowlist", str(FIXTURES / "allowlist.yaml")]
    result = _scan([*args, "--format", "json", "--out", str(out), "--fail-on", "none"])
    assert result.exit_code == 0
    actual = normalize((out / "mcpxw-report.json").read_text(encoding="utf-8"), tmp_path)
    _check_golden(actual, "kitchen_sink_allowlist.json", update_golden)


def test_finding_ids_match_formula(tmp_path: Path) -> None:
    import hashlib

    path = _place("kitchen_sink.json", tmp_path)
    out = tmp_path / "out"
    _scan(["--config", str(path), "--format", "json", "--out", str(out)])
    data = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    finding = next(f for f in data["findings"] if f["evidence"].startswith("env DB_PASSWORD"))
    material = "\x1f".join(["MCPXW-001", str(path), "openai-helper", "env:DB_PASSWORD"])
    assert finding["id"] == hashlib.sha256(material.encode()).hexdigest()[:12]
    assert len({f["id"] for f in data["findings"]}) == len(data["findings"])


def test_two_runs_are_identical(tmp_path: Path) -> None:
    path = _place("kitchen_sink.json", tmp_path)
    outputs = []
    for run in ("a", "b"):
        out = tmp_path / run
        _scan(["--config", str(path), "--format", "json,md,html,sarif", "--out", str(out)])
        texts = {}
        for report in sorted(out.iterdir()):
            text = report.read_text(encoding="utf-8")
            if report.suffix == ".json":
                text = json.dumps(normalize(text, tmp_path), sort_keys=True)
            else:
                data = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
                text = text.replace(data["generated_at"], "<GENERATED_AT>")
            texts[report.name] = text
        outputs.append(texts)
    assert outputs[0] == outputs[1]
