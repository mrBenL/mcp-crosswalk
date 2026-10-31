import hashlib

import pytest

from mcp_crosswalk.models import ServerEntry
from mcp_crosswalk.redact import (
    find_known_tokens,
    is_reference,
    is_secret_header,
    is_secret_name,
    looks_like_literal_secret,
    redact,
    redact_arg,
    redact_args,
    redact_server,
    redact_url,
    url_secrets,
)

GH = "ghp_" + "X" * 36


def test_redact_format() -> None:
    digest = hashlib.sha256(GH.encode()).hexdigest()[:8]
    assert redact(GH) == f"[REDACTED len=40 sha256={digest}]"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "${VAR}",
        "${env:VAR}",
        "${input:github-pat}",
        "$VAR",
        "%VAR%",
        "{{ secrets.token }}",
        "Bearer ${env:TOKEN}",
        "Bearer $TOKEN",
        "token ${X}",
    ],
)
def test_references_are_not_secrets(value: str) -> None:
    assert is_reference(value)
    assert not looks_like_literal_secret(value)


@pytest.mark.parametrize("value", ["abc123", "Bearer abc", "${A}literal", "prefix-${A}-suffix"])
def test_non_references(value: str) -> None:
    assert not is_reference(value)


@pytest.mark.parametrize(
    "name",
    [
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "API_KEY",
        "apiKey",
        "OPENAI_APIKEY",
        "DB_PASSWORD",
        "passwd",
        "GITLAB_PAT",
        "CLIENT_SECRET",
        "AWS_CREDENTIALS",
        "AUTH",
        "--api-key",
        "--token",
        "X-Api-Keys",
    ],
)
def test_secret_names(name: str) -> None:
    assert is_secret_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "PATH",
        "PYTHONPATH",
        "LOG_LEVEL",
        "AUTHOR",
        "TOKEN_URL",
        "API_KEY_FILE",
        "AWS_ACCESS_KEY_ID",
        "KEYCHAIN_PATH",
        "DATABASE_URI",
        "",
    ],
)
def test_non_secret_names(name: str) -> None:
    assert not is_secret_name(name)


@pytest.mark.parametrize(
    "value", ["true", "False", "1234", "/etc/creds.json", "~/x", "./x", "C:\\x"]
)
def test_values_that_are_not_literal_secrets(value: str) -> None:
    assert not looks_like_literal_secret(value)


def test_known_tokens() -> None:
    text = f"a {GH} b sk-{'Y' * 40} AKIA{'Q' * 16} AIza{'k' * 35} glpat-{'z' * 20}"
    assert len(find_known_tokens(text)) == 5
    assert find_known_tokens("sk-learn is a library") == []
    assert find_known_tokens("XAKIA" + "Q" * 16) == []


def test_secret_headers() -> None:
    assert is_secret_header("Authorization")
    assert is_secret_header("x-api-key")
    assert is_secret_header("Cookie")
    assert not is_secret_header("Accept")


def test_url_secrets_and_redaction() -> None:
    url = "https://user:hunter2hunter2@example.com/mcp?api_key=abcdef123456&mode=fast#frag"
    found = dict(url_secrets(url))
    assert found["userinfo password"] == "hunter2hunter2"
    assert found["query parameter api_key"] == "abcdef123456"
    redacted = redact_url(url)
    assert "hunter2hunter2" not in redacted
    assert "abcdef123456" not in redacted
    assert "mode=fast" in redacted
    assert redacted.startswith("https://user:[REDACTED len=14 ")
    assert "%20" not in redacted


def test_url_reference_values_are_kept() -> None:
    url = "https://example.com/mcp?token=${env:T}"
    assert url_secrets(url) == []
    assert redact_url(url) == url


def test_url_with_known_token_in_path() -> None:
    url = f"https://example.com/{GH}/mcp"
    assert url_secrets(url) == [("url", GH)]
    assert GH not in redact_url(url)


def test_url_with_token_username() -> None:
    url = f"https://{GH}@example.com/mcp"
    assert url_secrets(url) == [("userinfo", GH)]


def test_invalid_url_does_not_crash() -> None:
    bad = f"http://[::1/{GH}"
    assert url_secrets(bad) == [("url", GH)]
    assert GH not in redact_url(bad)


def test_redact_args() -> None:
    args = [
        "--api-key=abcdef12345",
        "--token",
        "zyxwvu98765",
        "Authorization: Bearer qwerty12345",
        GH,
    ]
    out = redact_args(args)
    joined = " ".join(out)
    for secret in ("abcdef12345", "zyxwvu98765", "qwerty12345", GH):
        assert secret not in joined
    assert out[1] == "--token"
    assert redact_arg("--mode=fast") == "--mode=fast"
    assert redact_args(["--token", "${T}"]) == ["--token", "${T}"]


def test_redact_server() -> None:
    entry = ServerEntry(
        name="s",
        client="generic",
        source_path="/x.json",
        command="node",
        args=["--token=abcdef123456"],
        env={"A": "literal", "B": "${B}"},
        url="https://h/mcp?key=abcdefabcdef",
        headers={"Authorization": "Bearer xyzxyzxyz123", "X-Ref": "${R}"},
    )
    safe = redact_server(entry)
    dumped = safe.model_dump_json()
    for secret in ("abcdef123456", "literal", "abcdefabcdef", "xyzxyzxyz123"):
        assert secret not in dumped
    assert safe.env["B"] == "${B}"
    assert safe.headers["X-Ref"] == "${R}"
    assert entry.env["A"] == "literal"  # original untouched


# --- Review finding R3: URL shapes that previously leaked ---------------------------------------

OPAQUE = "a1B2c3D4" + "e5F6g7H8" + "i9J0kLmN"
USER_TOKEN = "u" + "Z9" * 8 + "qQ"


@pytest.mark.parametrize(
    ("url", "secret"),
    [
        (f"http://{USER_TOKEN}@h.example.com/sse", USER_TOKEN),
        (f"http://h.example.com/mcp#access_token={OPAQUE}", OPAQUE),
        (f"http://h.example.com/mcp#x={OPAQUE}", OPAQUE),
        (f"http://h.example.com/mcp?k={OPAQUE}", OPAQUE),
        (f"http://h.example.com/mcp;token={OPAQUE}", OPAQUE),
        (f"http://h.example.com/a;session={OPAQUE}/b", OPAQUE),
    ],
)
def test_url_shapes_are_detected_and_redacted(url: str, secret: str) -> None:
    assert secret in {value for _, value in url_secrets(url)}
    redacted = redact_url(url)
    assert secret not in redacted
    assert redact(secret) in redacted


@pytest.mark.parametrize(
    "url",
    [
        "https://git@github.com/org/repo",
        "https://alice@h.example.com/mcp",
        "https://h.example.com/mcp?id=123e4567-e89b-12d3-a456-426614174000",
        "https://h.example.com/mcp?page=2&sort=name#section-2",
        "https://h.example.com/mcp;jsessionid=short",
        "https://h.example.com/mcp?redirect=https://other.example.com/path/to/a/long/place",
        "https://h.example.com/mcp?token=${env:TOKEN}",
    ],
)
def test_url_shapes_without_secrets_are_unchanged(url: str) -> None:
    assert url_secrets(url) == []
    assert redact_url(url) == url
