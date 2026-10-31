import csv
import io
import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from mcp_crosswalk import crosswalk as cw
from mcp_crosswalk.cli import app
from mcp_crosswalk.resources import crosswalk_dir

REPO = Path(__file__).resolve().parent.parent
runner = CliRunner()


@pytest.fixture
def cw_copy(tmp_path: Path) -> Path:
    target = tmp_path / "crosswalk"
    shutil.copytree(crosswalk_dir(), target)
    return target


def _edit(directory: Path, risk: str, change: Callable[[dict[str, Any]], None]) -> None:
    path = directory / f"{risk}.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _problems(directory: Path) -> list[str]:
    return cw.validate_crosswalk(directory)


def test_shipped_crosswalk_is_valid() -> None:
    assert cw.validate_crosswalk() == []


def test_shipped_crosswalk_quality() -> None:
    crosswalk = cw.load_crosswalk()
    assert sorted(crosswalk) == [f"MCP{n:02d}" for n in range(1, 11)]
    for risk_id, cw_file in crosswalk.items():
        assert cw_file.review_status == "reviewed", risk_id
        for mapping in cw_file.mappings:
            assert "MCP" in mapping.rationale, f"{risk_id} {mapping.control_id} not MCP-specific"


# --- Rule 1: schema / unknown keys -----------------------------------------------------------


def test_rule1_unknown_key_is_error(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][0].update({"surprise": 1}))
    assert any("MCP01.yaml: schema: mappings.0.surprise" in p for p in _problems(cw_copy))


def test_rule1_bad_enum_is_error(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][0].update({"relationship": "related_to"}))
    assert any("MCP01.yaml: schema: mappings.0.relationship" in p for p in _problems(cw_copy))


def test_rule1_unparseable_yaml(cw_copy: Path) -> None:
    (cw_copy / "MCP01.yaml").write_text("risk_id: [unclosed\n", encoding="utf-8")
    assert any("MCP01.yaml: cannot read YAML" in p for p in _problems(cw_copy))


# --- Rule 2: one file per risk, risk_id matches filename -------------------------------------


def test_rule2_missing_risk(cw_copy: Path) -> None:
    (cw_copy / "MCP05.yaml").unlink()
    problems = _problems(cw_copy)
    assert "MCP05.yaml: missing crosswalk file for OWASP risk MCP05" in problems


def test_rule2_risk_id_mismatch(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP02", lambda d: d.update({"risk_id": "MCP03"}))
    assert any("does not match filename" in p for p in _problems(cw_copy))


def test_rule2_unknown_risk_file(cw_copy: Path) -> None:
    shutil.copy(cw_copy / "MCP01.yaml", cw_copy / "MCP11.yaml")
    _edit(cw_copy, "MCP11", lambda d: d.update({"risk_id": "MCP11"}))
    assert "MCP11.yaml: 'MCP11' is not a risk in the OWASP catalog" in _problems(cw_copy)


def test_catalog_version_mismatch(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d.update({"catalog_version": "2024"}))
    assert any("catalog_version '2024'" in p for p in _problems(cw_copy))


# --- Rule 3: control exists and is not withdrawn ---------------------------------------------


def test_rule3_invalid_id(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][0].update({"control_id": "ZZ-99"}))
    assert any("ZZ-99: control ID not found" in p for p in _problems(cw_copy))


def test_rule3_csf_category_is_not_a_valid_target(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][4].update({"control_id": "PR.AA"}))
    assert any("PR.AA: control ID not found" in p for p in _problems(cw_copy))


def test_rule3_withdrawn_id(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][0].update({"control_id": "AC-2(10)"}))
    assert any("AC-2(10): control is withdrawn" in p for p in _problems(cw_copy))


def test_rule3_requires_display_form(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][0].update({"control_id": "ia-5.7"}))
    assert any("use the display form 'IA-5(7)'" in p for p in _problems(cw_copy))


# --- Rule 4: minimum counts --------------------------------------------------------------------


def test_rule4_minimum_counts(cw_copy: Path) -> None:
    def keep_few(d: dict[str, Any]) -> None:
        d["mappings"] = [m for m in d["mappings"] if m["framework"] == "nist-csf-2.0"][:1]

    _edit(cw_copy, "MCP08", keep_few)
    problems = _problems(cw_copy)
    assert "MCP08.yaml: has 0 nist-800-53r5 mappings (at least 3 required)" in problems
    assert "MCP08.yaml: has 1 nist-csf-2.0 mappings (at least 2 required)" in problems


# --- Rule 5: duplicates ------------------------------------------------------------------------


def test_rule5_duplicate(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"].append(dict(d["mappings"][0])))
    assert any("duplicate mapping" in p for p in _problems(cw_copy))


# --- Rules 6 and 7: check references -----------------------------------------------------------


def test_rule6_unknown_check(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][0].update({"check_ids": ["MCPXW-999"]}))
    assert any("'MCPXW-999' is not a registered check" in p for p in _problems(cw_copy))


def test_rule6_check_does_not_list_risk(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP03", lambda d: d["mappings"][0].update({"check_ids": ["MCPXW-001"]}))
    assert any("'MCPXW-001' does not list risk MCP03" in p for p in _problems(cw_copy))


def test_rule7_unreferenced_check(cw_copy: Path) -> None:
    def drop_009(d: dict[str, Any]) -> None:
        for mapping in d["mappings"]:
            mapping["check_ids"] = [c for c in mapping["check_ids"] if c != "MCPXW-009"]

    _edit(cw_copy, "MCP09", drop_009)
    assert "check MCPXW-009: not referenced by any crosswalk mapping" in _problems(cw_copy)


def test_rule7_extra_registered_check() -> None:
    index = {**cw.check_risk_index(), "MCPXW-900": ("MCP03",)}
    problems = cw.validate_crosswalk(check_risks=index)
    assert problems == ["check MCPXW-900: not referenced by any crosswalk mapping"]


# --- Rule 8: rationale length ------------------------------------------------------------------


def test_rule8_short_rationale(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][0].update({"rationale": "too short"}))
    assert any("rationale is 9 characters" in p for p in _problems(cw_copy))


def test_rule8_long_rationale(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d["mappings"][0].update({"rationale": "x" * 401}))
    assert any("rationale is 401 characters" in p for p in _problems(cw_copy))


def test_load_crosswalk_raises_on_invalid(cw_copy: Path) -> None:
    _edit(cw_copy, "MCP01", lambda d: d.update({"bogus": True}))
    with pytest.raises(cw.CrosswalkError) as info:
        cw.load_crosswalk(cw_copy)
    assert info.value.problems


# --- CLI and exports ---------------------------------------------------------------------------


def test_cli_validate_ok() -> None:
    result = runner.invoke(app, ["crosswalk", "validate"])
    assert result.exit_code == 0, result.output
    assert "Crosswalk valid: 10 risk files" in result.stdout


def test_cli_validate_reports_problems(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cw, "validate_crosswalk", lambda *_a, **_k: ["a problem", "another"])
    result = runner.invoke(app, ["crosswalk", "validate"])
    assert result.exit_code == 1
    assert "a problem" in result.output
    assert "2 problem(s)" in result.output


def test_committed_markdown_matches_fresh_export() -> None:
    fresh = cw.export_markdown(cw.load_crosswalk(), cw.load_owasp_catalog())
    assert (REPO / "docs" / "crosswalk.md").read_text(encoding="utf-8") == fresh


def test_committed_csv_matches_fresh_export() -> None:
    fresh = cw.export_csv(cw.load_crosswalk(), cw.load_owasp_catalog())
    assert (REPO / "docs" / "crosswalk.csv").read_text(encoding="utf-8") == fresh


def test_csv_and_json_exports_are_consistent() -> None:
    crosswalk, owasp = cw.load_crosswalk(), cw.load_owasp_catalog()
    rows = list(csv.DictReader(io.StringIO(cw.export_csv(crosswalk, owasp))))
    document = json.loads(cw.export_json(crosswalk, owasp))
    assert (
        len(rows) == len(document["mappings"]) == sum(len(f.mappings) for f in crosswalk.values())
    )
    assert all(row["control_title"] for row in rows)


@pytest.mark.parametrize("fmt", ["md", "csv", "json"])
def test_cli_export_to_file(tmp_path: Path, fmt: str) -> None:
    out = tmp_path / "sub" / f"crosswalk.{fmt}"
    result = runner.invoke(app, ["crosswalk", "export", "--format", fmt, "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8")


def test_cli_export_to_stdout() -> None:
    result = runner.invoke(app, ["crosswalk", "export", "--format", "csv"])
    assert result.exit_code == 0
    assert result.stdout.startswith("risk_id,risk_title,framework")


def test_cli_show_filters() -> None:
    result = runner.invoke(
        app, ["crosswalk", "show", "--risk", "mcp01", "--framework", "nist-csf-2.0"]
    )
    assert result.exit_code == 0
    assert "PR.AA-01" in result.stdout
    assert "IA-5(7)" not in result.stdout
    assert "MCP02" not in result.stdout


def test_cli_show_all_and_unknown_risk() -> None:
    result = runner.invoke(app, ["crosswalk", "show"])
    assert result.exit_code == 0
    assert "MCP10:" in result.stdout
    bad = runner.invoke(app, ["crosswalk", "show", "--risk", "MCP99"])
    assert bad.exit_code == 2


def test_markdown_header_reports_review_status() -> None:
    crosswalk = cw.load_crosswalk()
    owasp = cw.load_owasp_catalog()
    assert "all risk files are `reviewed` by the maintainer" in cw.export_markdown(crosswalk, owasp)
    one_draft = {
        k: v.model_copy(update={"review_status": "draft"}) if k == "MCP03" else v
        for k, v in crosswalk.items()
    }
    assert "`draft`: MCP03; all other risk files are `reviewed`" in cw.export_markdown(
        one_draft, owasp
    )
    all_draft = {k: v.model_copy(update={"review_status": "draft"}) for k, v in crosswalk.items()}
    assert "all risk files are `draft`" in cw.export_markdown(all_draft, owasp)
