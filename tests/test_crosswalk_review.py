"""The review worksheet export and the script that applies the owner's decisions."""

import csv
import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

from mcp_crosswalk import crosswalk as cw
from mcp_crosswalk.resources import crosswalk_dir

REPO = Path(__file__).resolve().parent.parent
COMMITTED = REPO / "docs" / "review" / "crosswalk-review.csv"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "crosswalk_review", REPO / "scripts" / "crosswalk_review.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["crosswalk_review"] = module
    spec.loader.exec_module(module)
    return module


review = _load_script()


def _keys(directory: Path) -> set[tuple[str, str, str]]:
    return {
        (risk_id, m.framework, m.control_id)
        for risk_id, f in cw.load_crosswalk(directory).items()
        for m in f.mappings
    }


def _read(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write(path: Path, rows: list[dict[str, str]], bom: bool = False) -> Path:
    with path.open("w", encoding="utf-8-sig" if bom else "utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture
def work(tmp_path: Path) -> Path:
    directory = tmp_path / "crosswalk"
    shutil.copytree(crosswalk_dir(), directory)
    # Start every test from an unreviewed crosswalk, independent of the shipped review state.
    for path in directory.glob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text.replace("review_status: reviewed", "review_status: draft").replace(
                "Reviewed by the maintainer.", "Draft, pending practitioner review."
            ),
            encoding="utf-8",
        )
    return directory


def _blank_rows(work: Path) -> list[dict[str, str]]:
    """A fresh, undecided worksheet for the crosswalk in ``work``."""
    return [dict(row) for row in review.export_rows(work)]


def _decide(
    rows: list[dict[str, str]], risk_id: str, control_id: str, decision: str, new: str = ""
) -> None:
    row = next(r for r in rows if r["risk_id"] == risk_id and r["control_id"] == control_id)
    row["decision"], row["new_relationship"] = decision, new


def test_export_has_every_mapping_with_control_text(tmp_path: Path) -> None:
    out = tmp_path / "ws.csv"
    assert review.main(["export", "--out", str(out)]) == 0
    rows = _read(out)
    assert list(rows[0]) == list(review.COLUMNS)
    assert len(rows) == 77
    assert {(r["risk_id"], r["framework"], r["control_id"]) for r in rows} == _keys(crosswalk_dir())
    assert all(r["control_text"] and r["control_title"] and r["rationale"] for r in rows)
    assert all(r["decision"] == r["new_relationship"] == r["notes"] == "" for r in rows)
    ia57 = next(r for r in rows if r["control_id"] == "IA-5(7)")
    assert "unencrypted static authenticators" in ia57["control_text"]


def test_committed_worksheet_rows_match_the_crosswalk() -> None:
    rows = _read(COMMITTED)
    assert {(r["risk_id"], r["framework"], r["control_id"]) for r in rows} == _keys(crosswalk_dir())


def test_preview_changes_nothing(work: Path, tmp_path: Path) -> None:
    rows = _blank_rows(work)
    for row in rows:
        row["decision"] = "keep"
    before = {p.name: p.read_bytes() for p in work.iterdir()}
    ws = _write(tmp_path / "ws.csv", rows)
    assert review.main(["apply", "--worksheet", str(ws), "--crosswalk-dir", str(work)]) == 0
    assert {p.name: p.read_bytes() for p in work.iterdir()} == before


def test_apply_change_drop_and_review_status(
    work: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = _blank_rows(work)
    for row in rows:
        if row["risk_id"] == "MCP07":
            row["decision"] = "keep"
    _decide(rows, "MCP07", "IA-9", "change", "subset_of")
    _decide(rows, "MCP07", "AC-17", "drop")
    _decide(rows, "MCP01", "IA-5(7)", "keep")  # MCP01 is only partly decided
    ws = _write(tmp_path / "ws.csv", rows, bom=True)
    original = (work / "MCP07.yaml").read_text(encoding="utf-8")
    original_mcp01 = (work / "MCP01.yaml").read_text(encoding="utf-8")

    code = review.main(["apply", "--worksheet", str(ws), "--crosswalk-dir", str(work), "--write"])
    assert code == 0, capsys.readouterr().err

    assert cw.validate_crosswalk(work) == []
    files = cw.load_crosswalk(work)
    mcp07 = {m.control_id: m for m in files["MCP07"].mappings}
    assert mcp07["IA-9"].relationship == "subset_of"
    assert "AC-17" not in mcp07
    assert len(mcp07) == 7
    assert files["MCP07"].review_status == "reviewed"
    assert files["MCP01"].review_status == "draft"
    text = (work / "MCP07.yaml").read_text(encoding="utf-8")
    # Comments and folded rationales survive; only the edited lines differ.
    assert text.splitlines()[0] == original.splitlines()[0]
    assert "Reviewed by the maintainer." in text.splitlines()[1]
    assert "rationale: >-" in text
    assert (work / "MCP01.yaml").read_text(encoding="utf-8") == original_mcp01
    out = capsys.readouterr().out
    assert "change MCP07 nist-800-53r5 IA-9 -> subset_of" in out
    assert "MCP01 stays as it is" in out


def test_invalid_result_writes_nothing(
    work: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = _blank_rows(work)
    for row in rows:
        if row["risk_id"] == "MCP07":
            row["decision"] = "drop"
    before = {p.name: p.read_bytes() for p in work.iterdir()}
    ws = _write(tmp_path / "ws.csv", rows)
    code = review.main(["apply", "--worksheet", str(ws), "--crosswalk-dir", str(work), "--write"])
    assert code == 1
    assert "nothing was written" in capsys.readouterr().err
    assert {p.name: p.read_bytes() for p in work.iterdir()} == before


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda rows: _decide(rows, "MCP07", "IA-9", "maybe"), "is not one of"),
        (lambda rows: _decide(rows, "MCP07", "IA-9", "change"), "change needs new_relationship"),
        (lambda rows: _decide(rows, "MCP07", "IA-9", "change", "related"), "change needs"),
        (lambda rows: _decide(rows, "MCP07", "IA-9", "keep", "equal"), "only used with change"),
        (lambda rows: _decide(rows, "MCP07", "IA-9", "", "equal"), "without a decision"),
        (lambda rows: rows.append(dict(rows[0])), "duplicate row"),
        (
            lambda rows: rows.append({**rows[0], "control_id": "AC-1", "decision": "keep"}),
            "not in the crosswalk",
        ),
    ],
)
def test_bad_worksheets_exit_2(
    edit: object, message: str, work: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = _blank_rows(work)
    assert callable(edit)
    edit(rows)
    ws = _write(tmp_path / "ws.csv", rows)
    code = review.main(["apply", "--worksheet", str(ws), "--crosswalk-dir", str(work), "--write"])
    assert code == 2
    assert message in capsys.readouterr().err


def test_missing_columns_exit_2(
    work: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ws = tmp_path / "ws.csv"
    ws.write_text("risk_id,control_id\nMCP07,IA-9\n", encoding="utf-8")
    assert review.main(["apply", "--worksheet", str(ws), "--crosswalk-dir", str(work)]) == 2
    assert "missing column" in capsys.readouterr().err
