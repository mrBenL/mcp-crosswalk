"""Secret detection primitives and redaction.

A detected secret only ever appears in output as ``[REDACTED len=<n> sha256=<first 8 hex>]``.
The hash prefix lets an operator confirm which credential leaked without revealing it.

References are not secrets: ``${VAR}``, ``${env:VAR}``, ``${input:id}``, ``$VAR``, ``%VAR%``,
``{{...}}``, and empty strings.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from mcp_crosswalk.models import ServerEntry

_REFERENCE = re.compile(
    r"\$\{[^}]*\}"  # ${VAR}, ${env:VAR}, ${input:id}
    r"|\$[A-Za-z_][A-Za-z0-9_]*"  # $VAR
    r"|%[A-Za-z_][A-Za-z0-9_]*%"  # %VAR%
    r"|\{\{.*?\}\}"  # {{ template }}
)
_AUTH_SCHEME = re.compile(r"(?i)\b(?:bearer|basic|token|apikey)\b")

_KNOWN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:github_pat_|ghp_|gho_|sk-ant-|sk-|xoxb-|xoxp-|glpat-)[A-Za-z0-9_\-]{16,}"
    r"|(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{30,}"
)

# Name parts that mark a key, flag, header, or query parameter as secret-bearing.
_SECRET_SUBSTRINGS = ("token", "secret", "password", "passwd", "credential")
_SECRET_EXACT = frozenset({"pat", "auth", "authorization", "apikey", "pwd"})
# A final name part that means the value is a locator or setting, not the secret itself.
_NON_SECRET_SUFFIXES = frozenset(
    {
        "url",
        "uri",
        "path",
        "file",
        "dir",
        "host",
        "port",
        "endpoint",
        "region",
        "type",
        "mode",
        "method",
        "enabled",
        "id",
        "name",
        "user",
        "username",
        "header",
        "expiry",
        "expires",
        "ttl",
    }
)
_LITERAL_NON_SECRETS = frozenset({"true", "false", "yes", "no", "on", "off", "null", "none"})
_PATH_LIKE = re.compile(r"^(?:/|~[/\\]|\.{1,2}[/\\]|[A-Za-z]:[\\/])")
SECRET_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "x-api-key"})


def redact(secret: str) -> str:
    """Return the redaction marker for a secret value."""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]
    return f"[REDACTED len={len(secret)} sha256={digest}]"


def is_reference(value: str) -> bool:
    """True if the value is empty or only references variables (optionally after an auth scheme)."""
    stripped = value.strip()
    if not stripped:
        return True
    if not _REFERENCE.search(stripped):
        return False
    remainder = _AUTH_SCHEME.sub("", _REFERENCE.sub("", stripped))
    return remainder.strip(" \t:=\"'") == ""


def name_parts(name: str) -> list[str]:
    """Split a key name into lowercase parts on separators and camelCase boundaries."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [part.lower() for part in re.split(r"[^A-Za-z0-9]+", spaced) if part]


def is_secret_name(name: str) -> bool:
    """True if a key, flag, header, or parameter name suggests its value is a secret."""
    parts = name_parts(name)
    if not parts or parts[-1] in _NON_SECRET_SUFFIXES:
        return False
    for part in parts:
        if any(s in part for s in _SECRET_SUBSTRINGS):
            return True
        if part in _SECRET_EXACT or part.endswith(("key", "keys")):
            return True
    return False


def looks_like_literal_secret(value: str) -> bool:
    """True for a non-empty value that is not a reference, a flag word, a number, or a path."""
    stripped = value.strip()
    if is_reference(stripped):
        return False
    if stripped.lower() in _LITERAL_NON_SECRETS or stripped.isdigit():
        return False
    return not _PATH_LIKE.match(stripped)


def find_known_tokens(text: str) -> list[str]:
    """Return substrings that match a known credential prefix (ghp_, sk-, AKIA, ...)."""
    return [m.group(0) for m in _KNOWN_TOKEN.finditer(text)]


def redact_known_tokens(text: str) -> str:
    return _KNOWN_TOKEN.sub(lambda m: redact(m.group(0)), text)


def _is_secret_param(name: str) -> bool:
    return is_secret_name(name) or name.lower() in {"key", "sig", "signature"}


_TOKEN_SEGMENT = re.compile(r"^[A-Za-z0-9_\-]{24,}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def looks_like_token_segment(segment: str) -> bool:
    """Heuristic for a credential embedded as a URL path segment (long, mixed, not a UUID)."""
    return (
        bool(_TOKEN_SEGMENT.match(segment))
        and not _UUID.match(segment)
        and any(c.isalpha() for c in segment)
        and any(c.isdigit() for c in segment)
        and len(set(segment)) >= 10
    )


_OPAQUE_VALUE = re.compile(r"^[A-Za-z0-9_\-.~+/=]{24,}$")


def looks_like_opaque_value(value: str) -> bool:
    """Heuristic for a credential-like parameter value whatever its name (``?k=<token>``)."""
    return (
        bool(_OPAQUE_VALUE.match(value))
        and not _UUID.match(value)
        and not _PATH_LIKE.match(value)
        and "://" not in value
        and len(set(value)) >= 8
        and (looks_like_token_segment(value) or len(value) >= 32 or value.isalpha())
    )


def _param_is_secret(name: str, value: str) -> bool:
    """Shared rule for query, fragment, and ``;name=value`` path parameters."""
    if is_reference(value):
        return False
    named = _is_secret_param(name) and looks_like_literal_secret(value)
    return named or looks_like_opaque_value(value)


def _username_is_secret(username: str | None, password: str | None) -> bool:
    """A long userinfo name with no password is a token used as the username (``TOKEN@host``)."""
    if not username or password or is_reference(username):
        return False
    return bool(find_known_tokens(username)) or (
        len(username) >= 16 and looks_like_literal_secret(username)
    )


def _redact_params(text: str, separator: str) -> tuple[str, list[tuple[str, str]]]:
    """Redact ``name=value`` pieces of a query, fragment, or path-parameter string."""
    pieces, found = [], []
    for piece in text.split(separator) if text else []:
        raw_name, sep, raw_value = piece.partition("=")
        name, value = unquote_plus(raw_name), unquote_plus(raw_value)
        if sep and _param_is_secret(name, value):
            pieces.append(f"{raw_name}={redact(value)}")
            found.append((name, value))
        else:
            pieces.append(piece)
    return separator.join(pieces), found


def _redact_path(path: str) -> tuple[str, list[tuple[str, str]]]:
    segments, found = [], []
    for segment in path.split("/"):
        head, *params = segment.split(";")
        if looks_like_token_segment(head):
            found.append(("path segment resembling a token", head))
            head = redact(head)
        redacted_params, secrets = _redact_params(";".join(params), ";")
        found += [(f"path parameter {name}", value) for name, value in secrets]
        segments.append(head + (";" + redacted_params if params else ""))
    return "/".join(segments), found


def url_secrets(url: str) -> list[tuple[str, str]]:
    """Return ``(location, secret)`` pairs for credentials embedded in a URL."""
    found: list[tuple[str, str]] = []
    try:
        parts = urlsplit(url)
        password = parts.password
        username = parts.username
    except ValueError:
        return [("url", token) for token in find_known_tokens(url)]
    if password and not is_reference(password):
        found.append(("userinfo password", password))
    elif username and find_known_tokens(username):
        found.append(("userinfo", username))
    elif _username_is_secret(username, password) and username:
        found.append(("userinfo username resembling a token", username))
    found += _redact_path(parts.path)[1]
    found += [(f"query parameter {n}", v) for n, v in _redact_params(parts.query, "&")[1]]
    found += [(f"fragment parameter {n}", v) for n, v in _redact_params(parts.fragment, "&")[1]]
    reported = {secret for _, secret in found}
    for token in find_known_tokens(url):
        if not any(token in secret for secret in reported):
            found.append(("url", token))
    return found


def redact_url(url: str) -> str:
    """Redact userinfo credentials, secret path/query/fragment values, and known tokens."""
    try:
        parts = urlsplit(url)
        password = parts.password
        username = parts.username
    except ValueError:
        return redact_known_tokens(url)
    netloc = parts.netloc
    if password and not is_reference(password):
        userinfo, _, hostport = netloc.rpartition("@")
        user = userinfo.split(":", 1)[0]
        netloc = f"{user}:{redact(password)}@{hostport}"
    elif username and _username_is_secret(username, password):
        _, _, hostport = netloc.rpartition("@")
        netloc = f"{redact(username)}@{hostport}"
    path = _redact_path(parts.path)[0]
    query = _redact_params(parts.query, "&")[0]
    fragment = _redact_params(parts.fragment, "&")[0]
    rebuilt = urlunsplit((parts.scheme, netloc, path, query, fragment))
    return redact_known_tokens(rebuilt)


def is_secret_header(name: str) -> bool:
    """True for header names that carry credentials (Authorization, X-API-Key, ...)."""
    return name.lower() in SECRET_HEADERS or is_secret_name(name)


# ``--name=value``, ``-n=value``, or a bare ``NAME=value`` (docker -e, env, shell assignments).
_ASSIGNMENT = re.compile(r"^(--?)?([A-Za-z_][A-Za-z0-9_.\-]*)=(.*)$", re.DOTALL)
_FLAG = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_\-]*$")
_HEADER = re.compile(r"^\s*([A-Za-z0-9\-]+)\s*:\s*(.+)$", re.DOTALL)


def classify_arg(arg: str) -> tuple[str, str | None]:
    """Redact one argument. Returns ``(redacted, kind)``; kind is None when nothing was secret.

    Kinds: ``header``, ``inline`` (whitespace-separated command text), ``assignment``, ``url``,
    ``token`` (known credential prefix). MCPXW-002 and the report inventory both use this function,
    so anything flagged is redacted and anything redacted is flagged.
    """
    header = _HEADER.match(arg)
    if header and is_secret_header(header.group(1)) and not is_reference(header.group(2)):
        return f"{header.group(1)}: {redact(header.group(2).strip())}", "header"
    if any(ch.isspace() for ch in arg.strip()):
        redacted = redact_command_line(arg)
        return redacted, ("inline" if redacted != arg else None)
    assignment = _ASSIGNMENT.match(arg)
    if (
        assignment
        and is_secret_name(assignment.group(2))
        and looks_like_literal_secret(assignment.group(3))
    ):
        prefix = (assignment.group(1) or "") + assignment.group(2)
        return f"{prefix}={redact(assignment.group(3))}", "assignment"
    if "://" in arg:
        redacted = redact_url(arg)
        return redacted, ("url" if redacted != arg else None)
    redacted = redact_known_tokens(arg)
    return redacted, ("token" if redacted != arg else None)


def classify_args(args: list[str]) -> list[tuple[str, str | None]]:
    """Classify every argument, treating ``--token VALUE`` as a pair (kind ``pair``)."""
    results: list[tuple[str, str | None]] = []
    for index, arg in enumerate(args):
        previous = args[index - 1] if index > 0 else ""
        if (
            _FLAG.match(previous)
            and is_secret_name(previous)
            and not arg.startswith("-")
            and looks_like_literal_secret(arg)
        ):
            results.append((redact(arg), "pair"))
        else:
            results.append(classify_arg(arg))
    return results


def redact_arg(arg: str) -> str:
    """Redact secrets inside a single command-line argument."""
    return classify_arg(arg)[0]


def redact_args(args: list[str]) -> list[str]:
    """Redact secrets in an argument list, including ``--token VALUE`` pairs."""
    return [redacted for redacted, _ in classify_args(args)]


def redact_command_line(text: str) -> str:
    """Redact secrets in whitespace-separated command text, keeping the original spacing."""
    parts = re.split(r"(\s+)", text)
    tokens = parts[::2]
    redacted_tokens = redact_args(tokens)
    out = []
    for index, part in enumerate(parts):
        out.append(redacted_tokens[index // 2] if index % 2 == 0 else part)
    return "".join(out)


def redact_mapping(values: dict[str, str]) -> dict[str, str]:
    """Redact every value that is not a pure reference (used for env and headers in output)."""
    return {k: (v if is_reference(v) else redact(v)) for k, v in sorted(values.items())}


def redact_server(entry: ServerEntry) -> ServerEntry:
    """Return a copy of a server entry that is safe to include in any report."""
    return entry.model_copy(
        update={
            "command": redact_command_line(entry.command) if entry.command is not None else None,
            "args": redact_args(entry.args),
            "env": redact_mapping(entry.env),
            "headers": redact_mapping(entry.headers),
            "url": redact_url(entry.url) if entry.url is not None else None,
        }
    )
