import builtins
import io
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import materialize

from mcp_crosswalk.discovery.adapters import read_config
from mcp_crosswalk.discovery.discover import discover, discover_configs
from mcp_crosswalk.discovery.locations import LOCATIONS, normalize_platform


def _populate(home: Path, appdata: Path, project: Path) -> None:
    """Create every known config file for every platform under fake roots."""
    for location in LOCATIONS:
        root = {"home": home, "appdata": appdata, "project": project}[location.root]
        materialize("generic.json", root.joinpath(*location.parts))


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    home, appdata, project = tmp_path / "home", tmp_path / "appdata", tmp_path / "project"
    _populate(home, appdata, project)
    return home, appdata, project


def _rel(paths: list[Path], base: Path) -> list[str]:
    return [p.relative_to(base).as_posix() for p in paths]


def test_discover_darwin(roots: tuple[Path, Path, Path], tmp_path: Path) -> None:
    home, appdata, project = roots
    found = _rel(discover(home, project, "darwin", appdata), tmp_path)
    assert found == [
        "home/Library/Application Support/Claude/claude_desktop_config.json",
        "home/.claude.json",
        "project/.mcp.json",
        "home/.cursor/mcp.json",
        "project/.cursor/mcp.json",
        "home/Library/Application Support/Code/User/mcp.json",
        "project/.vscode/mcp.json",
        "home/Library/Application Support/Code/User/settings.json",
        "project/.vscode/settings.json",
        "home/.codeium/windsurf/mcp_config.json",
    ]


def test_discover_win32(roots: tuple[Path, Path, Path], tmp_path: Path) -> None:
    home, appdata, project = roots
    found = _rel(discover(home, project, "win32", appdata), tmp_path)
    assert found == [
        "appdata/Claude/claude_desktop_config.json",
        "home/.claude.json",
        "project/.mcp.json",
        "home/.cursor/mcp.json",
        "project/.cursor/mcp.json",
        "appdata/Code/User/mcp.json",
        "project/.vscode/mcp.json",
        "appdata/Code/User/settings.json",
        "project/.vscode/settings.json",
        "home/.codeium/windsurf/mcp_config.json",
    ]


def test_discover_linux(roots: tuple[Path, Path, Path], tmp_path: Path) -> None:
    home, appdata, project = roots
    found = _rel(discover(home, project, "linux", appdata), tmp_path)
    assert found == [
        "home/.config/Claude/claude_desktop_config.json",
        "home/.claude.json",
        "project/.mcp.json",
        "home/.cursor/mcp.json",
        "project/.cursor/mcp.json",
        "home/.config/Code/User/mcp.json",
        "project/.vscode/mcp.json",
        "home/.config/Code/User/settings.json",
        "project/.vscode/settings.json",
        "home/.codeium/windsurf/mcp_config.json",
    ]


def test_discover_without_project_or_appdata(
    roots: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    home, _, _ = roots
    found = _rel(discover(home, None, "win32", None), tmp_path)
    assert found == [
        "home/.claude.json",
        "home/.cursor/mcp.json",
        "home/.codeium/windsurf/mcp_config.json",
    ]


def test_discover_empty_home(tmp_path: Path) -> None:
    assert discover(tmp_path / "empty", tmp_path / "empty", "linux", None) == []


def test_project_dir_equal_to_home_is_deduplicated(tmp_path: Path) -> None:
    materialize("cursor.json", tmp_path / ".cursor" / "mcp.json")
    found = discover_configs(tmp_path, tmp_path, "linux", None)
    assert len(found) == 1
    assert found[0].location.scope == "user"


def test_discovered_metadata(roots: tuple[Path, Path, Path]) -> None:
    home, appdata, project = roots
    found = discover_configs(home, project, "linux", appdata)
    clients = {(d.location.client, d.location.scope) for d in found}
    assert ("claude_code", "project") in clients
    assert ("vscode", "user") in clients


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("darwin", "darwin"),
        ("win32", "win32"),
        ("cygwin", "win32"),
        ("linux", "linux"),
        ("freebsd14", "linux"),
    ],
)
def test_normalize_platform(value: str, expected: str) -> None:
    assert normalize_platform(value) == expected


@pytest.fixture
def path_audit(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Record every filesystem path that discovery or parsing touches."""
    touched: list[str] = []
    real_open = builtins.open
    real_io_open = io.open
    real_stat = os.stat

    def audited_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        touched.append(os.fspath(file))
        return real_open(file, *args, **kwargs)

    def audited_io_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        touched.append(os.fspath(file))
        return real_io_open(file, *args, **kwargs)

    def audited_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        touched.append(os.fspath(path))
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", audited_open)
    monkeypatch.setattr(io, "open", audited_io_open)
    monkeypatch.setattr(os, "stat", audited_stat)
    yield touched


def test_discovery_and_parsing_never_touch_real_home(
    tmp_path: Path, path_audit: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home, appdata, project = tmp_path / "home", tmp_path / "appdata", tmp_path / "project"
    _populate(home, appdata, project)
    path_audit.clear()
    # Point the real-environment variables somewhere obviously wrong; discovery must not use them.
    monkeypatch.setenv("HOME", "/nonexistent-real-home")
    monkeypatch.setenv("APPDATA", "/nonexistent-real-appdata")
    for platform in ("darwin", "win32", "linux"):
        for found in discover_configs(home, project, platform, appdata):
            read_config(found.path, client=found.location.client, scope=found.location.scope)
    assert path_audit, "audit hook recorded nothing; the test would be vacuous"
    base = str(tmp_path)
    outside = [p for p in path_audit if not p.startswith(base)]
    assert outside == []
