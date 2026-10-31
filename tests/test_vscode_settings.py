"""MCP servers in VS Code ``settings.json`` (V02 N2b).

Claude Code protects ``.vscode/`` inside the repo, so fixtures use neutral names and are copied into
``tmp_path`` under their real names.
"""

import json
from pathlib import Path

import pytest
from conftest import materialize
from typer.testing import CliRunner

from mcp_crosswalk import cli
from mcp_crosswalk.cli import app
from mcp_crosswalk.discovery.adapters import guess_client, read_config
from mcp_crosswalk.discovery.discover import discover_configs
from mcp_crosswalk.reporters import FORMATS

runner = CliRunner()
MARKERS = (
    "UNRELATED_PROXY_MARKER",
    "UNRELATED_THEME_MARKER",
    "UNRELATED_EXCLUDE_MARKER",
    "UNRELATED_SERVERS_MARKER",
    "UNRELATED_NON_OBJECT_MARKER",
    "editor.fontSize",
    "http.proxy",
)


def _user_settings(home: Path) -> Path:
    return materialize(
        "vscode_settings.jsonc", home / ".config" / "Code" / "User" / "settings.json"
    )


def test_nested_shape_with_comments_and_trailing_commas(tmp_path: Path) -> None:
    path = _user_settings(tmp_path)
    record, entries = read_config(path)
    assert record.status == "ok"
    assert record.client == "vscode"
    assert record.servers == 2
    by_name = {e.name: e for e in entries}
    assert sorted(by_name) == ["github", "remote-docs"]
    assert by_name["github"].scope == "user"
    assert by_name["github"].transport == "stdio"
    assert by_name["github"].env == {"GITHUB_PERSONAL_ACCESS_TOKEN": "${input:gh-token}"}
    assert by_name["remote-docs"].transport == "http"
    assert by_name["remote-docs"].url == "http://docs.internal.example.com/mcp"


def test_flat_key_shape_ignores_top_level_servers(tmp_path: Path) -> None:
    path = materialize("vscode_settings_flat.jsonc", tmp_path / ".vscode" / "settings.json")
    record, entries = read_config(path)
    assert record.status == "ok"
    assert (record.client, record.servers) == ("vscode", 1)
    assert [(e.name, e.scope, e.command) for e in entries] == [("fetch", "project", "uvx")]


def test_nested_wins_over_flat_for_same_name(tmp_path: Path) -> None:
    path = tmp_path / ".vscode" / "settings.json"
    path.parent.mkdir()
    document = {
        "mcp": {"servers": {"a": {"command": "nested"}}},
        "mcp.servers": {"a": {"command": "flat"}, "b": {"command": "only-flat"}},
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    _, entries = read_config(path)
    assert [(e.name, e.command) for e in entries] == [("a", "nested"), ("b", "only-flat")]


def test_settings_without_mcp_keys(tmp_path: Path) -> None:
    path = materialize("vscode_settings_no_mcp.jsonc", tmp_path / ".vscode" / "settings.json")
    record, entries = read_config(path)
    assert record.status == "ok"
    assert record.error is None
    assert (record.servers, entries) == (0, [])


def test_mcp_without_servers_and_non_object_servers(tmp_path: Path) -> None:
    path = tmp_path / ".vscode" / "settings.json"
    path.parent.mkdir()
    path.write_text('{"mcp": {"inputs": []}, "mcp.servers": ["x"]}', encoding="utf-8")
    record, entries = read_config(path)
    assert (record.status, entries) == ("ok", [])


def test_malformed_settings_is_parse_error(tmp_path: Path) -> None:
    path = tmp_path / ".vscode" / "settings.json"
    path.parent.mkdir()
    path.write_text('{"mcp": {"servers": {', encoding="utf-8")
    record, entries = read_config(path)
    assert record.status == "parse_error"
    assert entries == []


@pytest.mark.parametrize(
    ("parts", "expected"),
    [
        ((".vscode", "settings.json"), ("vscode", "project")),
        (("Code", "User", "settings.json"), ("vscode", "user")),
        (("other", "settings.json"), ("generic", "unknown")),
    ],
)
def test_guess_client_for_settings(parts: tuple[str, ...], expected: tuple[str, str]) -> None:
    assert guess_client(Path("/x").joinpath(*parts)) == expected


@pytest.mark.parametrize(
    ("platform", "root", "parts"),
    [
        ("darwin", "home", ("Library", "Application Support", "Code", "User", "settings.json")),
        ("win32", "appdata", ("Code", "User", "settings.json")),
        ("linux", "home", (".config", "Code", "User", "settings.json")),
    ],
)
def test_discovery_per_platform(
    tmp_path: Path, platform: str, root: str, parts: tuple[str, ...]
) -> None:
    home, appdata, project = tmp_path / "home", tmp_path / "appdata", tmp_path / "project"
    base = {"home": home, "appdata": appdata}[root]
    user = materialize("vscode_settings.jsonc", base.joinpath(*parts))
    proj = materialize("vscode_settings_flat.jsonc", project / ".vscode" / "settings.json")
    found = discover_configs(home, project, platform, appdata)
    assert [(d.path, d.location.client, d.location.scope) for d in found] == [
        (user, "vscode", "user"),
        (proj, "vscode", "project"),
    ]


def test_discover_scan_never_echoes_other_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    _user_settings(home)
    materialize("vscode_settings_flat.jsonc", project / ".vscode" / "settings.json")
    materialize("vscode_settings_no_mcp.jsonc", home / ".config" / "Code" / "User" / "mcp.json")
    monkeypatch.setattr(cli, "discovery_roots", lambda _p: (home, project, "linux", None))
    out = tmp_path / "out"
    args = ["scan", "--discover", "--format", ",".join(FORMATS), "--out", str(out)]
    result = runner.invoke(app, [*args, "--fail-on", "none"])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert sorted(s["name"] for s in report["servers"]) == ["fetch", "github", "remote-docs"]
    assert {s["client"] for s in report["servers"]} == {"vscode"}
    assert any(f["check_id"] == "MCPXW-007" for f in report["findings"])
    for path in out.iterdir():
        text = path.read_text(encoding="utf-8")
        for marker in MARKERS:
            assert marker not in text, (path.name, marker)
    for marker in MARKERS:
        assert marker not in result.output


def test_r2_non_vscode_settings_json_is_parsed_normally(tmp_path: Path) -> None:
    # Review finding R2: other clients also name their MCP config settings.json.
    path = tmp_path / "gem" / "settings.json"
    path.parent.mkdir()
    path.write_text('{"mcpServers": {"remote": {"url": "http://evil.example.com/mcp"}}}', "utf-8")
    record, entries = read_config(path)
    assert (record.status, record.client, record.servers) == ("ok", "generic", 1)
    assert entries[0].url == "http://evil.example.com/mcp"
    out = tmp_path / "out"
    result = runner.invoke(app, ["scan", "--config", str(path), "--out", str(out)])
    assert result.exit_code == 1  # MCPXW-007 high finding
    report = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert any(f["check_id"] == "MCPXW-007" for f in report["findings"])


@pytest.mark.parametrize(
    ("parts", "settings_mode"),
    [
        ((".vscode", "settings.json"), True),
        (("Code", "User", "settings.json"), True),
        (("code", "user", "SETTINGS.JSON"), True),
        (("gem", "settings.json"), False),
        (("User", "settings.json"), False),
        ((".vscode", "mcp.json"), False),
    ],
)
def test_r2_settings_mode_only_for_vscode_locations(
    parts: tuple[str, ...], settings_mode: bool
) -> None:
    from mcp_crosswalk.discovery.adapters import is_settings_file

    assert is_settings_file(Path("/x").joinpath(*parts)) is settings_mode
