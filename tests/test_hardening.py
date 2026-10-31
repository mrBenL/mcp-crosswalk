"""Design-principle tests: offline, read-only, never executes, secrets stay redacted."""

import ast
import socket
from pathlib import Path
from typing import Any

import pytest
from conftest import FIXTURES, materialize
from typer.testing import CliRunner

from mcp_crosswalk import cli, resources
from mcp_crosswalk.cli import app

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "mcp_crosswalk"
runner = CliRunner()


class NetworkUsedError(AssertionError):
    pass


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise NetworkUsedError("network access attempted")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def _all_fixtures(root: Path) -> list[Path]:
    return [
        materialize("kitchen_sink.json", root / "kitchen_sink.json"),
        materialize("hostile.json", root / "hostile.json"),
        materialize("malformed.json", root / "malformed.json"),
        materialize("vscode_project.jsonc", root / "proj" / ".vscode" / "mcp.json"),
        materialize("claude_code_user.json", root / "home" / ".claude.json"),
        materialize("url_shapes.json", root / "url_shapes.json"),  # review finding R3
    ]


def test_full_scan_works_with_sockets_disabled(
    tmp_path: Path, no_network: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    configs = _all_fixtures(tmp_path / "in")
    home, project = tmp_path / "in" / "home", tmp_path / "in" / "proj"
    monkeypatch.setattr(cli, "discovery_roots", lambda _p: (home, project, "linux", None))
    args = ["scan", "--discover", "--format", "json,md,html,sarif", "--out", str(tmp_path / "out")]
    args += ["--allowlist", str(FIXTURES / "allowlist.yaml")]
    for config in configs[:3]:
        args += ["--config", str(config)]
    result = runner.invoke(app, args)
    assert not isinstance(result.exception, NetworkUsedError)
    assert result.exit_code == 1, result.output  # high findings present
    assert len(list((tmp_path / "out").iterdir())) == 4
    for command in (["crosswalk", "validate"], ["checks", "list"], ["crosswalk", "show"]):
        assert runner.invoke(app, command).exit_code == 0


def test_no_output_format_contains_a_full_secret(
    tmp_path: Path, fake_secrets: dict[str, str]
) -> None:
    configs = _all_fixtures(tmp_path / "in")
    out = tmp_path / "out"
    args = ["scan", "--format", "json,md,html,sarif,poam", "--out", str(out)]
    for config in configs:
        args += ["--config", str(config)]
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    reports = sorted(out.iterdir())
    assert len(reports) == 5
    assert "mcpxw-poam.csv" in {p.name for p in reports}
    for report in reports:
        text = report.read_text(encoding="utf-8")
        assert "[REDACTED len=" in text, report.name
        for placeholder, value in fake_secrets.items():
            assert value not in text, f"{placeholder} leaked into {report.name}"
    for value in fake_secrets.values():
        assert value not in result.output


def _snapshot(root: Path) -> dict[str, tuple[int, int]]:
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in root.rglob("*")
        if p.is_file()
    }


def test_scan_writes_only_inside_out(tmp_path: Path) -> None:
    configs = _all_fixtures(tmp_path / "in")
    before = _snapshot(tmp_path)
    out = tmp_path / "out"
    args = ["scan", "--format", "json,md,html,sarif,poam", "--out", str(out)]
    for config in configs:
        args += ["--config", str(config)]
    runner.invoke(app, args)
    after = _snapshot(tmp_path)
    changed = {k for k in after if before.get(k) != after[k]}
    reports = {f"out/mcpxw-report.{ext}" for ext in ("json", "md", "html", "sarif")}
    assert changed == reports | {"out/mcpxw-poam.csv"}


# --- Static audit of the runtime package -------------------------------------------------------

FORBIDDEN_MODULES = {
    "socket",
    "ssl",
    "http",
    "urllib.request",
    "http.client",
    "requests",
    "httpx",
    "aiohttp",
    "subprocess",
    "multiprocessing",
    "ctypes",
    "pty",
}
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_OS_PREFIXES = ("system", "popen", "spawn", "exec", "startfile", "fork", "posix_spawn")


def _python_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_runtime_package_imports_no_network_or_process_modules() -> None:
    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for name in names:
                if name in FORBIDDEN_MODULES or name.split(".")[0] in {"socket", "subprocess"}:
                    offenders.append(f"{path.name}: {name}")
    assert offenders == []


def test_runtime_package_has_no_dynamic_execution() -> None:
    offenders = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
                offenders.append(f"{path.name}:{node.lineno} {func.id}")
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
                and func.attr.startswith(FORBIDDEN_OS_PREFIXES)
            ):
                offenders.append(f"{path.name}:{node.lineno} os.{func.attr}")
    assert offenders == []


def test_yaml_is_only_loaded_safely() -> None:
    for path in _python_files():
        text = path.read_text(encoding="utf-8")
        assert "yaml.load(" not in text, path.name
        assert "yaml.unsafe_load" not in text, path.name


# --- Packaged data lookup ----------------------------------------------------------------------


def test_data_root_prefers_packaged_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = tmp_path / "mcp_crosswalk"
    (package / "data" / "crosswalk").mkdir(parents=True)
    (package / "data" / "catalog").mkdir(parents=True)
    monkeypatch.setattr(resources.importlib.resources, "files", lambda _name: package)
    resources.data_root.cache_clear()
    try:
        assert resources.data_root() == package / "data"
    finally:
        resources.data_root.cache_clear()


def test_data_root_missing_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resources.importlib.resources, "files", lambda _name: tmp_path)
    monkeypatch.setattr(resources, "__file__", str(tmp_path / "a" / "b" / "resources.py"))
    resources.data_root.cache_clear()
    try:
        with pytest.raises(resources.DataNotFoundError):
            resources.data_root()
    finally:
        resources.data_root.cache_clear()
