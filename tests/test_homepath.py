"""Path privacy: reports show the home directory as ~ unless --full-paths is given."""

import json
from pathlib import Path

import jsonschema
import pytest
from typer.testing import CliRunner

from mcp_crosswalk.cli import app
from mcp_crosswalk.homepath import home_pattern
from mcp_crosswalk.reporters import FORMATS
from mcp_crosswalk.reporters.sarif import artifact_location

runner = CliRunner()
SARIF_SCHEMA = Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json"
CONFIG = {
    "mcpServers": {
        "files": {"command": "node", "args": ["server.js", "HOME_DIR/projects/demo"]},
        "remote": {"url": "http://mcp.example.com/mcp"},
    }
}


def _sub(pattern_home: str, text: str) -> str:
    pattern = home_pattern(pattern_home)
    assert pattern is not None
    return pattern.sub("~", text)


def test_posix_home_replaced_only_at_a_path_boundary() -> None:
    assert _sub("/home/alex", "/home/alex/.claude.json") == "~/.claude.json"
    assert _sub("/home/alex", "/home/alex") == "~"
    assert _sub("/home/alex", "arg /home/alex/src, then /home/alex") == "arg ~/src, then ~"
    assert _sub("/home/alex", "/home/alexis/x") == "/home/alexis/x"
    assert _sub("/home/alex", "/home/alex.bak/x") == "/home/alex.bak/x"
    assert _sub("/home/alex", "/HOME/ALEX/x") == "/HOME/ALEX/x"


def test_windows_home_matches_either_separator_and_any_case() -> None:
    home = "C:\\Users\\Alex"
    assert _sub(home, "C:\\Users\\Alex\\.cursor\\mcp.json") == "~\\.cursor\\mcp.json"
    assert _sub(home, "c:/users/alex/AppData/x.json") == "~/AppData/x.json"
    assert _sub(home, "C:\\Users\\Alexis\\x") == "C:\\Users\\Alexis\\x"


@pytest.mark.parametrize("home", ["/", "C:\\", ""])
def test_root_or_empty_home_is_not_replaced(home: str) -> None:
    assert home_pattern(home) is None


def test_sarif_location_for_home_relative_paths() -> None:
    assert artifact_location("~/.claude.json") == {"uri": ".claude.json", "uriBaseId": "HOME"}
    assert artifact_location("~\\AppData\\Roaming\\Claude\\x y.json") == {
        "uri": "AppData/Roaming/Claude/x%20y.json",
        "uriBaseId": "HOME",
    }
    assert artifact_location("/etc/mcp.json") == {"uri": "file:///etc/mcp.json"}


def _scan_under_fake_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str
) -> tuple[Path, Path]:
    home = tmp_path / "home" / "alexuser"
    home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    assert Path.home() == home
    config = home / ".claude.json"
    config.write_text(
        json.dumps(CONFIG, indent=2).replace("HOME_DIR", home.as_posix()), encoding="utf-8"
    )
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["scan", "--config", str(config), "--format", ",".join(FORMATS), "--out", str(out), *extra],
    )
    assert result.exit_code == 1, result.output
    return home, out


def test_reports_show_home_as_tilde_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, out = _scan_under_fake_home(tmp_path, monkeypatch)
    files = sorted(out.iterdir())
    assert len(files) == len(FORMATS)
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert str(home) not in text, path.name
        assert home.as_posix() not in text, path.name
        assert "alexuser" not in text, path.name

    report = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert {i["path"] for i in report["inputs"]} == {"~/.claude.json"}
    assert {f["source_path"] for f in report["findings"]} == {"~/.claude.json"}
    files_server = next(s for s in report["servers"] if s["name"] == "files")
    assert files_server["args"] == ["server.js", "~/projects/demo"]

    sarif = json.loads((out / "mcpxw-report.sarif").read_text(encoding="utf-8"))
    jsonschema.validate(sarif, json.loads(SARIF_SCHEMA.read_text(encoding="utf-8")))
    run = sarif["runs"][0]
    assert "HOME" in run["originalUriBaseIds"]
    for result in run["results"]:
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"] == {"uri": ".claude.json", "uriBaseId": "HOME"}
        # Line numbers still come from the real file.
        assert location["region"]["startLine"] > 1


def test_full_paths_flag_keeps_real_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, out = _scan_under_fake_home(tmp_path, monkeypatch, "--full-paths")
    report = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert {f["source_path"] for f in report["findings"]} == {str(home / ".claude.json")}
    sarif = json.loads((out / "mcpxw-report.sarif").read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    assert "originalUriBaseIds" not in run
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": (home / ".claude.json").as_uri()
    }


def test_finding_ids_do_not_depend_on_the_display_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, out = _scan_under_fake_home(tmp_path, monkeypatch)
    short_report = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    short_ids = sorted(f["id"] for f in short_report["findings"])
    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(Path.home() / ".claude.json"),
            "--out",
            str(tmp_path / "full"),
            "--full-paths",
        ],
    )
    assert result.exit_code == 1, result.output
    full_report = json.loads((tmp_path / "full" / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert sorted(f["id"] for f in full_report["findings"]) == short_ids


def test_root_home_leaves_paths_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/")
    monkeypatch.setenv("USERPROFILE", "/")
    config = tmp_path / "generic.json"
    config.write_text(json.dumps(CONFIG), encoding="utf-8")
    result = runner.invoke(app, ["scan", "--config", str(config), "--out", str(tmp_path / "o")])
    assert result.exit_code == 1, result.output
    report = json.loads((tmp_path / "o" / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert {f["source_path"] for f in report["findings"]} == {str(config)}
