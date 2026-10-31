"""Repository hygiene: no hidden characters or secret-shaped strings in source files."""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("src", "tests", "scripts", "crosswalk", "catalog/owasp-mcp", "docs", "schema")
TEXT_SUFFIXES = {".py", ".json", ".jsonc", ".yaml", ".md", ".csv", ".j2", ".toml", ".sarif"}
INVISIBLE = re.compile("[\u200b-\u200f\u061c\ufeff\u202a-\u202e\u2066-\u2069]")
SECRET_SHAPED = re.compile(
    r"(ghp_|gho_|github_pat_|xox[bp]-|glpat-)[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}"
)


def _files() -> list[Path]:
    files = []
    for directory in SOURCE_DIRS:
        for path in (REPO / directory).rglob("*"):
            if path.is_file() and path.suffix in TEXT_SUFFIXES and "__pycache__" not in path.parts:
                files.append(path)
    return files


def test_no_invisible_or_bidi_characters_in_source() -> None:
    offenders = [
        str(p.relative_to(REPO))
        for p in _files()
        if INVISIBLE.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def _claim_texts() -> dict[str, str]:
    paths = [REPO / "README.md", *(REPO / "docs").glob("*.md"), *(REPO / "src").rglob("*.py")]
    paths += list((REPO / "src").rglob("*.j2"))
    return {str(p.relative_to(REPO)): p.read_text(encoding="utf-8") for p in paths}


def test_no_cmmc_alignment_claims() -> None:
    # CMMC Level 2 references SP 800-171 Rev 2; every mention of CMMC must sit in a negation.
    mentions = 0
    for name, text in _claim_texts().items():
        flat = " ".join(text.split())
        for match in re.finditer("CMMC", flat):
            mentions += 1
            window = flat[max(0, match.start() - 160) : match.end() + 160]
            assert re.search(r"\b(not|no|nothing)\b", window), (name, window)
        assert not re.search(r"(?i)cmmc[- ](aligned|compliant|ready)", flat), name
    assert mentions > 0


def test_readme_makes_no_first_or_only_claims() -> None:
    text = " ".join((REPO / "README.md").read_text(encoding="utf-8").split()).lower()
    for phrase in ("the first", "the only", "first-ever", "only tool", "unique"):
        assert phrase not in text, phrase


def test_no_secret_shaped_strings_in_repo() -> None:
    offenders = [
        str(p.relative_to(REPO))
        for p in _files()
        if SECRET_SHAPED.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []
