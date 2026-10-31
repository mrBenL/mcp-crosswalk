"""Known MCP client config locations (best known as of 2026-10; update as clients change).

Each row says which client and scope a file belongs to, which root it is relative to
(``home``, ``appdata`` (Windows ``%APPDATA%``), or ``project``), the relative path, and the
platforms (``darwin``, ``win32``, ``linux``) where it applies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from mcp_crosswalk.models import ClientId, Scope

Root = Literal["home", "appdata", "project"]
Platform = Literal["darwin", "win32", "linux"]
ALL_PLATFORMS: tuple[Platform, ...] = ("darwin", "win32", "linux")


@dataclass(frozen=True)
class Location:
    client: ClientId
    scope: Scope
    root: Root
    parts: tuple[str, ...]
    platforms: tuple[Platform, ...] = ALL_PLATFORMS


LOCATIONS: tuple[Location, ...] = (
    # Claude Desktop
    Location(
        "claude_desktop",
        "user",
        "home",
        ("Library", "Application Support", "Claude", "claude_desktop_config.json"),
        ("darwin",),
    ),
    Location(
        "claude_desktop", "user", "appdata", ("Claude", "claude_desktop_config.json"), ("win32",)
    ),
    Location(
        "claude_desktop",
        "user",
        "home",
        (".config", "Claude", "claude_desktop_config.json"),
        ("linux",),
    ),
    # Claude Code
    Location("claude_code", "user", "home", (".claude.json",)),
    Location("claude_code", "project", "project", (".mcp.json",)),
    # Cursor
    Location("cursor", "user", "home", (".cursor", "mcp.json")),
    Location("cursor", "project", "project", (".cursor", "mcp.json")),
    # VS Code
    Location(
        "vscode",
        "user",
        "home",
        ("Library", "Application Support", "Code", "User", "mcp.json"),
        ("darwin",),
    ),
    Location("vscode", "user", "appdata", ("Code", "User", "mcp.json"), ("win32",)),
    Location("vscode", "user", "home", (".config", "Code", "User", "mcp.json"), ("linux",)),
    Location("vscode", "project", "project", (".vscode", "mcp.json")),
    # VS Code settings.json: servers under "mcp": {"servers": ...} (or a flat "mcp.servers")
    Location(
        "vscode",
        "user",
        "home",
        ("Library", "Application Support", "Code", "User", "settings.json"),
        ("darwin",),
    ),
    Location("vscode", "user", "appdata", ("Code", "User", "settings.json"), ("win32",)),
    Location("vscode", "user", "home", (".config", "Code", "User", "settings.json"), ("linux",)),
    Location("vscode", "project", "project", (".vscode", "settings.json")),
    # Windsurf
    Location("windsurf", "user", "home", (".codeium", "windsurf", "mcp_config.json")),
)


def normalize_platform(platform: str) -> Platform:
    """Map a ``sys.platform`` value to one of the table's platform keys (default ``linux``)."""
    if platform.startswith("win") or platform == "cygwin":
        return "win32"
    if platform == "darwin":
        return "darwin"
    return "linux"
