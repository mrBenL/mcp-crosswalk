"""Discover MCP client config files in known locations.

Every root is a parameter: this module never consults the real environment (home directory,
``%APPDATA%``, current directory, or ``sys.platform``). The CLI supplies real values; tests supply
temporary directories.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp_crosswalk.discovery.locations import LOCATIONS, Location, normalize_platform


@dataclass(frozen=True)
class DiscoveredConfig:
    path: Path
    location: Location


def discover_configs(
    home: Path,
    project_dir: Path | None,
    platform: str,
    appdata: Path | None,
) -> list[DiscoveredConfig]:
    """Return existing config files for the given roots and platform, with location metadata."""
    plat = normalize_platform(platform)
    roots: dict[str, Path | None] = {"home": home, "appdata": appdata, "project": project_dir}
    found: list[DiscoveredConfig] = []
    seen: set[Path] = set()
    for location in LOCATIONS:
        if plat not in location.platforms:
            continue
        root = roots[location.root]
        if root is None:
            continue
        candidate = root.joinpath(*location.parts)
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        found.append(DiscoveredConfig(path=candidate, location=location))
    return found


def discover(
    home: Path, project_dir: Path | None, platform: str, appdata: Path | None
) -> list[Path]:
    """Return the paths of existing MCP client config files in known locations."""
    return [d.path for d in discover_configs(home, project_dir, platform, appdata)]
