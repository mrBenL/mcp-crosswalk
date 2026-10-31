from pathlib import Path

import pytest
from conftest import CONFIGS, materialize

from mcp_crosswalk.discovery.adapters import (
    guess_client,
    infer_transport,
    parse_document,
    read_config,
)
from mcp_crosswalk.models import ServerEntry


def _summary(entries: list[ServerEntry]) -> list[tuple[str, str, str, str | None]]:
    return [(e.name, e.transport, e.scope, e.project) for e in entries]


def test_claude_desktop(tmp_path: Path) -> None:
    path = materialize("claude_desktop.json", tmp_path / "claude_desktop_config.json")
    record, entries = read_config(path)
    assert record.status == "ok"
    assert record.client == "claude_desktop"
    assert record.servers == 2
    assert _summary(entries) == [
        ("filesystem", "stdio", "user", None),
        ("memory", "stdio", "user", None),
    ]
    fs = entries[0]
    assert fs.command == "npx"
    assert fs.args == [
        "@modelcontextprotocol/server-filesystem@2025.8.21",
        "/Users/alex/projects/demo",
    ]
    assert fs.raw_keys == ["args", "command"]
    assert fs.source_path == str(path)


def test_claude_code_project_file(tmp_path: Path) -> None:
    path = materialize("claude_code_project.json", tmp_path / ".mcp.json")
    record, entries = read_config(path)
    assert record.client == "claude_code"
    assert _summary(entries) == [
        ("github", "stdio", "project", None),
        ("sentry", "http", "project", None),
    ]
    assert entries[0].env == {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}
    assert entries[1].url == "https://mcp.sentry.example.com/mcp"
    assert entries[1].headers == {"Authorization": "Bearer ${SENTRY_TOKEN}"}
    assert entries[1].raw_keys == ["headers", "type", "url"]


def test_claude_code_user_file_with_projects(tmp_path: Path) -> None:
    path = materialize("claude_code_user.json", tmp_path / ".claude.json")
    record, entries = read_config(path)
    assert record.status == "ok"
    assert record.client == "claude_code"
    assert _summary(entries) == [
        ("memory", "stdio", "user", None),
        ("postgres", "stdio", "project", "/home/alex/app"),
        ("fetch", "stdio", "project", "/home/alex/site"),
    ]


def test_cursor(tmp_path: Path) -> None:
    path = materialize("cursor.json", tmp_path / ".cursor" / "mcp.json")
    record, entries = read_config(path)
    assert record.client == "cursor"
    assert _summary(entries) == [
        ("fetch", "stdio", "unknown", None),
        ("linear", "sse", "unknown", None),
    ]


def test_vscode_jsonc(tmp_path: Path) -> None:
    path = materialize("vscode_project.jsonc", tmp_path / ".vscode" / "mcp.json")
    record, entries = read_config(path)
    assert record.status == "ok", record.error
    assert record.client == "vscode"
    assert _summary(entries) == [
        ("github", "stdio", "project", None),
        ("docs", "http", "project", None),
    ]
    assert entries[0].env == {"GITHUB_PERSONAL_ACCESS_TOKEN": "${input:github-pat}"}
    assert entries[1].url == "https://docs.example.com/mcp"
    assert entries[1].headers == {"X-API-Key": "${env:DOCS_KEY}"}


def test_windsurf_server_url(tmp_path: Path) -> None:
    path = materialize("windsurf.json", tmp_path / ".codeium" / "windsurf" / "mcp_config.json")
    record, entries = read_config(path)
    assert record.client == "windsurf"
    assert _summary(entries) == [
        ("remote-search", "http", "user", None),
        ("time", "stdio", "user", None),
    ]
    assert entries[0].url == "https://search.example.com/mcp"
    assert "serverUrl" in entries[0].raw_keys


def test_generic(tmp_path: Path) -> None:
    path = materialize("generic.json", tmp_path / "some-config.json")
    record, entries = read_config(path)
    assert record.client == "generic"
    assert _summary(entries) == [("sqlite", "stdio", "unknown", None)]


def test_kitchen_sink_parses_all_servers(tmp_path: Path) -> None:
    path = materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json")
    record, entries = read_config(path)
    assert record.status == "ok"
    assert record.servers == 11
    transports = {e.name: e.transport for e in entries}
    assert transports["remote-bridge"] == "stdio"
    assert transports["legacy-remote"] == "http"
    assert transports["analytics"] == "sse"
    assert transports["docs-remote"] == "sse"
    assert transports["postgres-container"] == "stdio"


def test_malformed_file_is_parse_error(tmp_path: Path) -> None:
    path = materialize("malformed.json", tmp_path / "malformed.json")
    record, entries = read_config(path)
    assert record.status == "parse_error"
    assert record.error is not None
    assert "line" in record.error
    assert entries == []


def test_hostile_file_parses_without_crash(tmp_path: Path) -> None:
    path = materialize("hostile.json", tmp_path / "hostile.json")
    record, entries = read_config(path)
    assert record.status == "ok"
    names = [e.name for e in entries]
    assert "<script>alert(1)</script>" in names
    assert "not-an-object" not in names
    numbers = next(e for e in entries if e.name == "numbers")
    assert numbers.command == "42"
    assert numbers.args == ["1", "true", "", '{"k": "v"}']
    assert numbers.env == {"N": "1"}
    single = next(e for e in entries if e.name == "args-string")
    assert single.args == ["single-arg.js"]


def test_huge_integer_is_parse_error(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_text('{"mcpServers": {"s": {"args": [' + "9" * 5000 + "]}}}", encoding="utf-8")
    record, entries = read_config(path)
    assert record.status == "parse_error"
    assert entries == []


def test_unexpected_value_error_is_parse_error_without_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_crosswalk.discovery import adapters

    def boom(*_args: object, **_kwargs: object) -> list[ServerEntry]:
        raise ValueError("contains SECRET-CONTENT from the config")

    monkeypatch.setattr(adapters, "parse_document", boom)
    record, _ = read_config(materialize("generic.json", tmp_path / "g.json"))
    assert record.status == "parse_error"
    assert "SECRET-CONTENT" not in (record.error or "")


def test_missing_file_is_read_error(tmp_path: Path) -> None:
    record, entries = read_config(tmp_path / "nope.json")
    assert record.status == "read_error"
    assert entries == []


def test_non_utf8_file_is_read_error(tmp_path: Path) -> None:
    path = tmp_path / "latin1.json"
    path.write_bytes(b'{"mcpServers": {"caf\xe9": {}}}')
    record, _ = read_config(path)
    assert record.status == "read_error"


def test_oversized_file_is_not_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_crosswalk.discovery import adapters

    monkeypatch.setattr(adapters, "MAX_CONFIG_BYTES", 10)
    path = materialize("generic.json", tmp_path / "big.json")
    record, entries = read_config(path)
    assert record.status == "read_error"
    assert "larger than" in (record.error or "")
    assert entries == []


@pytest.mark.parametrize("document", [[], "text", 3, None])
def test_non_object_top_level_is_parse_error(tmp_path: Path, document: object) -> None:
    import json

    path = tmp_path / "x.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    record, _ = read_config(path)
    assert record.status == "parse_error"


def test_empty_containers() -> None:
    assert parse_document({}, client="generic", source_path="x", scope="unknown") == []
    doc = {"mcpServers": [], "servers": "x", "projects": {"p": "x", "q": {"mcpServers": None}}}
    assert parse_document(doc, client="generic", source_path="x", scope="unknown") == []


@pytest.mark.parametrize(
    ("explicit", "command", "url", "expected"),
    [
        ("stdio", None, None, "stdio"),
        ("streamable-http", None, "https://x/sse", "http"),
        ("SSE", None, "https://x/mcp", "sse"),
        ("weird", "node", None, "stdio"),
        (None, None, "https://x.example/sse", "sse"),
        (None, None, "https://x.example/sse/", "sse"),
        (None, None, "https://x.example/mcp", "http"),
        (None, None, "relative/sse", "sse"),
        (None, None, None, "unknown"),
    ],
)
def test_infer_transport(
    explicit: str | None, command: str | None, url: str | None, expected: str
) -> None:
    assert infer_transport(explicit, command, url) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            "/x/Library/Application Support/Claude/claude_desktop_config.json",
            ("claude_desktop", "user"),
        ),
        ("/home/a/.claude.json", ("claude_code", "user")),
        ("/p/.mcp.json", ("claude_code", "project")),
        ("/p/.cursor/mcp.json", ("cursor", "unknown")),
        ("/p/.vscode/mcp.json", ("vscode", "project")),
        ("/home/a/.config/Code/User/mcp.json", ("vscode", "user")),
        ("/home/a/.codeium/windsurf/mcp_config.json", ("windsurf", "user")),
        ("/srv/data/whatever.json", ("generic", "unknown")),
    ],
)
def test_guess_client(path: str, expected: tuple[str, str]) -> None:
    assert guess_client(Path(path)) == expected


def test_fixture_files_contain_no_secret_shaped_strings() -> None:
    from conftest import FAKE_SECRETS

    for path in CONFIGS.iterdir():
        text = path.read_text(encoding="utf-8")
        for value in FAKE_SECRETS.values():
            assert value not in text
        for prefix in ("ghp_", "xoxb-", "AKIA", "github_pat_", "glpat-"):
            assert prefix not in text, f"{path.name} contains {prefix}"
