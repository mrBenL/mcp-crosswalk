"""Shared test helpers.

Fixture files never contain anything secret-shaped. They hold placeholders such as
``__FAKE_GITHUB_PAT__`` that are replaced at runtime with fake values built by concatenation, so the
repository stays free of strings that secret scanners would flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
CONFIGS = FIXTURES / "configs"

FAKE_SECRETS: dict[str, str] = {
    "__FAKE_GITHUB_PAT__": "ghp_" + "X" * 36,
    "__FAKE_OPENAI_KEY__": "sk-" + "Y" * 40,
    "__FAKE_AWS_KEY__": "AKIA" + "Q" * 16,
    "__FAKE_PASSWORD__": "hunter" + "2" * 10,
    "__FAKE_SLACK_TOKEN__": "xoxb-" + "1" * 12 + "-" + "Z" * 24,
    "__FAKE_URL_TOKEN__": "T" * 8 + "u" * 16,
    "__FAKE_BEARER__": "W" * 12 + "v" * 20,
    "__FAKE_DB_SECRET__": "Pg" + "q" * 14 + "R" * 8,
    # An opaque token with no recognizable prefix, used in URL positions (review finding R3).
    "__FAKE_OPAQUE__": "a1B2c3D4" + "e5F6g7H8" + "i9J0kLmN",
    "__FAKE_USER_TOKEN__": "u" + "Z9" * 8 + "qQ",
}


def materialize(fixture: str, dest: Path) -> Path:
    """Copy ``tests/fixtures/configs/<fixture>`` to ``dest``, substituting fake secrets."""
    text = (CONFIGS / fixture).read_text(encoding="utf-8")
    for placeholder, value in FAKE_SECRETS.items():
        text = text.replace(placeholder, value)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


@pytest.fixture
def fake_secrets() -> dict[str, str]:
    return dict(FAKE_SECRETS)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="Rewrite tests/golden/*.json from the current output instead of comparing.",
    )


@pytest.fixture
def update_golden(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--update-golden"))
