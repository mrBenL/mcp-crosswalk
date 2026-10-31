"""Report renderers and the writer that places them in the output directory."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

from mcp_crosswalk.homepath import shorten_paths
from mcp_crosswalk.models import Report
from mcp_crosswalk.reporters import html, json_reporter, markdown, poam, sarif
from mcp_crosswalk.safewrite import UnsafeOutputError, write_files

Renderer = Callable[[Report], str]

FORMATS: dict[str, tuple[Renderer, str]] = {
    "json": (json_reporter.render, "mcpxw-report.json"),
    "md": (markdown.render, "mcpxw-report.md"),
    "html": (html.render, "mcpxw-report.html"),
    "sarif": (sarif.render, "mcpxw-report.sarif"),
    "poam": (poam.render, "mcpxw-poam.csv"),
}
# Formats that carry the full report, including the coverage matrix. POA&M rows are findings only.
REPORT_FORMATS = ("json", "md", "html", "sarif")


class OutputError(RuntimeError):
    """The report cannot be written safely."""


def parse_formats(value: str) -> list[str]:
    """Parse a comma-separated format list, preserving the canonical order."""
    requested = {part.strip().lower() for part in value.split(",") if part.strip()}
    unknown = requested - set(FORMATS)
    if unknown or not requested:
        raise ValueError(
            f"unknown format(s): {', '.join(sorted(unknown)) or '(none)'}; "
            f"choose from {', '.join(FORMATS)}"
        )
    return [name for name in FORMATS if name in requested]


def write_reports(
    report: Report, formats: Iterable[str], out_dir: Path, home: Path | None = None
) -> list[Path]:
    """Render each format and write it to a fixed file name directly inside ``out_dir``.

    When ``home`` is given, the home directory is shown as ``~`` in every format (path privacy).
    SARIF still reads line numbers from the real config paths.

    Only those fixed names are ever written. An existing symlink at a target path is refused so a
    planted link cannot redirect the write outside ``out_dir``. Every target is checked before any
    file is written, and each file is replaced atomically.
    """
    shown = shorten_paths(report, home) if home is not None else report
    rendered: dict[str, str] = {}
    for name in formats:
        renderer, filename = FORMATS[name]
        if name == "sarif":
            rendered[filename] = sarif.render(shown, line_source=report)
        else:
            rendered[filename] = renderer(shown)
    try:
        return write_files(out_dir, rendered)
    except UnsafeOutputError as exc:
        raise OutputError(str(exc)) from exc
