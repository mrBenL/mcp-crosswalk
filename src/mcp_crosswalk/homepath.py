"""Path privacy: show the user's home directory as ``~`` in written reports.

Reports name config file paths, Claude Code project paths, and paths found in server arguments. On a
real machine those start with the home directory, which usually contains the user's name. By
default every report string has the home directory replaced with ``~`` before rendering; ``scan
--full-paths`` turns this off. Finding IDs are computed from the real paths before this step, so
they do not change with the setting.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from mcp_crosswalk.models import Report

HOME_MARK = "~"
# The match must end at a path boundary, so /home/alex does not match inside /home/alexis.
_BOUNDARY = r"(?![\w.\-])"


def home_pattern(home: str) -> re.Pattern[str] | None:
    """A pattern matching ``home`` in text, or None when ``home`` is too short to replace safely.

    A home of ``/`` or ``C:\\`` would turn every absolute path into ``~``, so it is left alone.
    Windows homes match with either separator and in any letter case.
    """
    windows = PureWindowsPath(home)
    if windows.drive:
        if len(windows.parts) < 2:
            return None
        variants = {str(windows), windows.as_posix()}
        flags = re.IGNORECASE
    else:
        posix = PurePosixPath(home)
        if len(posix.parts) < 2:
            return None
        variants = {str(posix)}
        flags = re.NOFLAG
    alternatives = "|".join(re.escape(v) for v in sorted(variants, key=len, reverse=True))
    return re.compile(f"(?:{alternatives}){_BOUNDARY}", flags)


def shorten_paths(report: Report, home: Path | str) -> Report:
    """A copy of ``report`` with the home directory shown as ``~`` in every string value."""
    pattern = home_pattern(str(home))
    if pattern is None:
        return report

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return pattern.sub(HOME_MARK, value)
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, dict):
            return {key: walk(item) for key, item in value.items()}
        return value

    return Report.model_validate(walk(report.model_dump()))
