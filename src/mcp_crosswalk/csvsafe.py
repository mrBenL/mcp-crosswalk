"""CSV formula-injection protection for every CSV the tool writes.

Config values are attacker-controlled. A spreadsheet treats a cell that starts with ``=``, ``+``,
``-``, ``@``, tab, or carriage return as a formula (``=HYPERLINK(...)``, DDE payloads), so such a
cell is prefixed with a single quote, which spreadsheets show as text.
"""

from __future__ import annotations

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: object) -> str:
    """Return the cell text, quote-prefixed when it could be read as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def safe_row(row: dict[str, object]) -> dict[str, str]:
    return {key: safe_cell(value) for key, value in row.items()}
