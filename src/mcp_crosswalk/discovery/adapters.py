"""Parse MCP client config files into normalized ``ServerEntry`` objects.

Parsing is tolerant: unknown keys are ignored, odd value types are coerced or skipped, and nothing
in the file is ever executed. A file that cannot be read or parsed yields an ``InputRecord`` with an
error status instead of raising.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import urlsplit

from mcp_crosswalk import jsonc
from mcp_crosswalk.models import ClientId, InputRecord, Scope, ServerEntry, Transport

# Refuse to parse unreasonably large files. Claude Code's ~/.claude.json accumulates per-project
# history, so the cap is generous.
MAX_CONFIG_BYTES = 50 * 1024 * 1024

_TRANSPORT_TYPES: dict[str, Transport] = {
    "stdio": "stdio",
    "http": "http",
    "streamable-http": "http",
    "streamablehttp": "http",
    "streamable_http": "http",
    "sse": "sse",
}


class ConfigParseError(ValueError):
    """The file is not a parseable MCP config."""


def _as_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, bool | int | float):
        return json.dumps(value)
    return json.dumps(value, sort_keys=True)


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_as_str(v) for v in value]
    if value is None:
        return []
    return [_as_str(value)]


def _str_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): _as_str(v) for k, v in value.items()}


def infer_transport(explicit: Any, command: str | None, url: str | None) -> Transport:
    """Explicit ``type`` wins; else a command means stdio, and a URL ending in /sse means SSE."""
    if isinstance(explicit, str):
        mapped = _TRANSPORT_TYPES.get(explicit.strip().lower())
        if mapped is not None:
            return mapped
    if command:
        return "stdio"
    if url:
        path = urlsplit(url).path if "://" in url else url
        return "sse" if path.rstrip("/").endswith("/sse") else "http"
    return "unknown"


def parse_server(
    name: str,
    raw: dict[str, Any],
    *,
    client: ClientId,
    source_path: str,
    scope: Scope,
    project: str | None = None,
) -> ServerEntry:
    command_value = raw.get("command")
    command = _as_str(command_value) if command_value is not None else None
    url_value = raw.get("url", raw.get("serverUrl"))
    url = _as_str(url_value) if url_value is not None else None
    return ServerEntry(
        name=str(name),
        client=client,
        source_path=source_path,
        scope=scope,
        transport=infer_transport(raw.get("type"), command, url),
        command=command,
        args=_str_list(raw.get("args")),
        env=_str_dict(raw.get("env")),
        url=url,
        headers=_str_dict(raw.get("headers")),
        raw_keys=sorted(str(k) for k in raw),
        project=project,
    )


def _servers_from_container(
    container: Any,
    *,
    client: ClientId,
    source_path: str,
    scope: Scope,
    project: str | None = None,
) -> list[ServerEntry]:
    if not isinstance(container, dict):
        return []
    entries = []
    for name, raw in container.items():
        if isinstance(raw, dict):
            entries.append(
                parse_server(
                    str(name),
                    raw,
                    client=client,
                    source_path=source_path,
                    scope=scope,
                    project=project,
                )
            )
    return entries


def parse_settings_document(
    document: dict[str, Any], *, client: ClientId, source_path: str, scope: Scope
) -> list[ServerEntry]:
    """Extract servers from a VS Code ``settings.json``.

    Servers live under ``"mcp": {"servers": {...}}``; a flat ``"mcp.servers": {...}`` key is
    tolerated too (nested wins when both name the same server). Every other settings key is ignored
    and never copied into the report.
    """
    nested = document.get("mcp")
    containers = [nested.get("servers") if isinstance(nested, dict) else None]
    containers.append(document.get("mcp.servers"))
    entries: list[ServerEntry] = []
    seen: set[str] = set()
    for container in containers:
        for entry in _servers_from_container(
            container, client=client, source_path=source_path, scope=scope
        ):
            if entry.name not in seen:
                seen.add(entry.name)
                entries.append(entry)
    return entries


def parse_document(
    document: Any,
    *,
    client: ClientId,
    source_path: str,
    scope: Scope,
    settings: bool = False,
) -> list[ServerEntry]:
    """Extract servers from a parsed config document.

    Accepts ``mcpServers`` (Claude Desktop, Claude Code, Cursor, Windsurf, generic) and ``servers``
    (VS Code) containers, plus Claude Code's ``projects.<path>.mcpServers``. With ``settings=True``
    the document is a VS Code ``settings.json`` and only its MCP keys are read.
    """
    if not isinstance(document, dict):
        raise ConfigParseError("top-level value is not a JSON object")
    if settings:
        return parse_settings_document(
            document, client=client, source_path=source_path, scope=scope
        )
    entries = _servers_from_container(
        document.get("mcpServers"), client=client, source_path=source_path, scope=scope
    )
    entries += _servers_from_container(
        document.get("servers"), client=client, source_path=source_path, scope=scope
    )
    projects = document.get("projects")
    if isinstance(projects, dict):
        for project_path, project in sorted(projects.items(), key=lambda kv: str(kv[0])):
            if isinstance(project, dict):
                entries += _servers_from_container(
                    project.get("mcpServers"),
                    client=client,
                    source_path=source_path,
                    scope="project",
                    project=str(project_path),
                )
    return entries


def guess_client(path: PurePath) -> tuple[ClientId, Scope]:
    """Guess the client and scope of an explicitly named config file from its path."""
    name = path.name.lower()
    parent = path.parent.name.lower()
    if name == "claude_desktop_config.json":
        return "claude_desktop", "user"
    if name == ".claude.json":
        return "claude_code", "user"
    if name == ".mcp.json":
        return "claude_code", "project"
    if name == "mcp.json" and parent == ".cursor":
        return "cursor", "unknown"
    if name == "mcp.json" and parent == ".vscode":
        return "vscode", "project"
    if name == "mcp.json" and parent == "user" and path.parent.parent.name.lower() == "code":
        return "vscode", "user"
    if name == "settings.json" and parent == ".vscode":
        return "vscode", "project"
    if name == "settings.json" and parent == "user" and path.parent.parent.name.lower() == "code":
        return "vscode", "user"
    if name == "mcp_config.json" and parent == "windsurf":
        return "windsurf", "user"
    return "generic", "unknown"


def is_settings_file(path: PurePath) -> bool:
    """True for a VS Code settings file (``.vscode/settings.json`` or ``Code/User/settings.json``).

    Those hold MCP servers only under their ``mcp`` keys. Any other ``settings.json`` (other
    clients use the name too) is parsed like a normal config, so a top-level ``mcpServers`` is read.
    """
    if path.name.lower() != "settings.json":
        return False
    parent = path.parent.name.lower()
    return parent == ".vscode" or (parent == "user" and path.parent.parent.name.lower() == "code")


def read_config(
    path: Path,
    *,
    client: ClientId | None = None,
    scope: Scope | None = None,
) -> tuple[InputRecord, list[ServerEntry]]:
    """Read and parse one config file. Never raises for bad input; errors go in the InputRecord."""
    guessed_client, guessed_scope = guess_client(path)
    client = client or guessed_client
    scope = scope or guessed_scope
    source_path = str(path)
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return (
                InputRecord(
                    path=source_path,
                    client=client,
                    status="read_error",
                    error=f"file larger than {MAX_CONFIG_BYTES} bytes; not parsed",
                ),
                [],
            )
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        error = f"{type(exc).__name__}: {getattr(exc, 'strerror', None) or exc}"
        return InputRecord(path=source_path, client=client, status="read_error", error=error), []
    try:
        document = jsonc.loads(text)
        entries = parse_document(
            document,
            client=client,
            source_path=source_path,
            scope=scope,
            settings=is_settings_file(path),
        )
    except (jsonc.JsoncError, ConfigParseError) as exc:
        return InputRecord(
            path=source_path, client=client, status="parse_error", error=str(exc)
        ), []
    except ValueError as exc:
        # Any other value error: report the type only, since messages can quote config content.
        error = f"unparseable config ({type(exc).__name__})"
        return InputRecord(path=source_path, client=client, status="parse_error", error=error), []
    record = InputRecord(path=source_path, client=client, status="ok", servers=len(entries))
    return record, entries
