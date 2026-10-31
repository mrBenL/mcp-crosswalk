"""Comment- and trailing-comma-tolerant JSON loading (JSONC, as used by VS Code).

The stripper is string-aware: ``//`` or ``/*`` inside a JSON string (for example in a URL) is kept.
Removed comments are replaced by spaces (newlines kept) so error line numbers stay accurate.
"""

from __future__ import annotations

import json
from typing import Any


class JsoncError(ValueError):
    """Raised when text is not valid JSON or JSONC."""


def strip_jsonc(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments and trailing commas outside of strings."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                raise JsoncError("unterminated block comment")
            comment = text[i : end + 2]
            out.append("".join("\n" if c == "\n" else " " for c in comment))
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return _strip_trailing_commas("".join(out))


def _strip_trailing_commas(text: str) -> str:
    """Drop a comma that is followed (after whitespace) by ``}`` or ``]``, outside of strings."""
    out: list[str] = []
    in_string = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                out.append(" ")
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def loads(text: str) -> Any:
    """Parse JSON or JSONC text. Raises JsoncError with a readable message on failure."""
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        return json.loads(strip_jsonc(text))
    except json.JSONDecodeError as exc:
        raise JsoncError(
            f"invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    except RecursionError as exc:
        raise JsoncError("JSON nesting too deep") from exc
    except JsoncError:
        raise
    except ValueError as exc:
        # For example, Python's limit on integer literal digits (CVE-2020-10735 mitigation).
        raise JsoncError(f"invalid JSON value: {type(exc).__name__}") from exc
