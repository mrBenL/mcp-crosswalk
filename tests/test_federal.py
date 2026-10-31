"""Derived federal context: 800-53 baselines and 800-171r3 links (V02 N3).

Expected values were read from the vendored NIST files (catalog/frameworks/); the tests that use
synthetic documents pin the parsing rules independently of those files.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from conftest import materialize
from typer.testing import CliRunner

from mcp_crosswalk import crosswalk as cw
from mcp_crosswalk import federal
from mcp_crosswalk.cli import app
from mcp_crosswalk.engine import ScanTarget, scan
from mcp_crosswalk.reporters import html, markdown
from mcp_crosswalk.resources import frameworks_dir

REPO = Path(__file__).resolve().parent.parent
runner = CliRunner()


def _raw_ids(name: federal.BaselineName) -> set[str]:
    """Independent read of a baseline file: every control ID at any depth."""
    doc = json.loads((frameworks_dir() / federal.BASELINE_FILES[name]).read_bytes())
    ids: set[str] = set()

    def walk(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            ids.add(node["id"])
            walk(node.get("controls", []))

    for group in doc["catalog"]["groups"]:
        walk(group.get("controls", []))
    return ids


# --- Baselines ------------------------------------------------------------------------------


def test_ac2_baselines_match_vendored_files() -> None:
    assert federal.baselines_for("nist-800-53r5", "AC-2") == ["LOW", "MODERATE", "HIGH"]
    assert "ac-2" in _raw_ids("LOW")
    assert "ac-2" not in _raw_ids("PRIVACY")


def test_control_absent_from_low() -> None:
    assert "ac-2.1" not in _raw_ids("LOW")
    assert federal.baselines_for("nist-800-53r5", "AC-2(1)") == ["MODERATE", "HIGH"]


def test_control_in_no_baseline() -> None:
    assert all("ia-5.7" not in _raw_ids(name) for name in federal.BASELINES)
    assert federal.baselines_for("nist-800-53r5", "IA-5(7)") == []


def test_oscal_form_input_and_csf() -> None:
    assert federal.baselines_for("nist-800-53r5", "ac-2.1") == ["MODERATE", "HIGH"]
    assert federal.baselines_for("nist-csf-2.0", "PR.AA-01") == []
    assert federal.baselines_for("nist-800-53r5", "not an id") == []
    assert federal.sp800_171r3_for("nist-csf-2.0", "PR.AA-01") == []
    assert federal.sp800_171r3_for("nist-800-53r5", "bogus") == []


@pytest.mark.parametrize("name", federal.BASELINES)
def test_membership_equals_independent_read(name: str) -> None:
    assert federal.baseline_members(name) == _raw_ids(name)


def test_parse_baseline_excludes_withdrawn() -> None:
    doc = {
        "catalog": {
            "groups": [
                {
                    "controls": [
                        {"id": "ac-1"},
                        {"id": "ac-2", "controls": [{"id": "ac-2.1"}]},
                        {"id": "ac-9", "props": [{"name": "status", "value": "withdrawn"}]},
                    ]
                }
            ]
        }
    }
    assert federal.parse_baseline(json.dumps(doc).encode()) == {"ac-1", "ac-2", "ac-2.1"}


# --- 800-171r3 derived links ----------------------------------------------------------------


def test_ia5_1_links_to_password_management() -> None:
    assert "03.05.07" in federal.sp800_171r3_for("nist-800-53r5", "IA-5(1)")


def test_exact_match_only_no_inheritance() -> None:
    # 03.05.07 cites IA-05(01) (and SP 800-63-3), not IA-05, so the base control does not get it.
    assert "03.05.07" not in federal.sp800_171r3_for("nist-800-53r5", "IA-5")


def test_withdrawn_requirements_excluded_from_vendored_index() -> None:
    doc = json.loads((frameworks_dir() / federal.SP800_171R3_FILE).read_bytes())
    withdrawn = set()
    for group in doc["catalog"]["groups"]:
        for req in group.get("controls", []):
            if any(p.get("name") == "status" for p in req.get("props", [])):
                withdrawn.add(req["id"].removeprefix("SP_800_171_"))
    assert len(withdrawn) == 33
    linked = {n for numbers in federal.sp800_171r3_index().values() for n in numbers}
    assert linked
    assert not linked & withdrawn


def _synthetic_171() -> dict[str, Any]:
    return {
        "catalog": {
            "groups": [
                {
                    "controls": [
                        {
                            "id": "SP_800_171_03.05.07",
                            "links": [
                                {"href": "#r1", "rel": "reference"},
                                {"href": "#r2", "rel": "reference"},
                                {"href": "#r3", "rel": "reference"},
                            ],
                        },
                        {
                            "id": "SP_800_171_03.01.13",
                            "props": [{"name": "status", "value": "withdrawn"}],
                            "links": [{"href": "#r4", "rel": "reference"}],
                        },
                        {
                            "id": "SP_800_171_03.01.01",
                            "links": [
                                {"href": "#r4", "rel": "reference"},
                                {"href": "03.13.08", "rel": "addressed_by"},
                            ],
                        },
                        {"id": "not-a-requirement", "links": [{"href": "#r4", "rel": "reference"}]},
                    ]
                }
            ],
            "back-matter": {
                "resources": [
                    {"uuid": "r1", "title": "IA-05(01)"},
                    {"uuid": "r2", "title": "SP 800-63-3"},
                    {"uuid": "r3", "title": "Protecting Controlled Unclassified Information"},
                    {"uuid": "r4", "title": "AC-02"},
                ]
            },
        }
    }


def test_parse_rules_on_synthetic_catalog() -> None:
    index = federal.parse_sp800_171r3(json.dumps(_synthetic_171()).encode())
    # Non-800-53 references ignored; withdrawn 03.01.13 and non-requirement IDs excluded.
    assert index == {"ia-5.1": ("03.05.07",), "ac-2": ("03.01.01",)}


def test_every_index_key_is_a_real_800_53_control() -> None:
    from mcp_crosswalk.catalogs import load_catalog

    entries = load_catalog("nist-800-53r5").entries
    assert set(federal.sp800_171r3_index()) <= set(entries)


# --- Surfaces -------------------------------------------------------------------------------


def test_docs_have_derived_columns_and_labels() -> None:
    text = (REPO / "docs" / "crosswalk.md").read_text(encoding="utf-8")
    assert "| Baselines | 800-171r3 (derived) |" in text
    assert federal.SP800_171R3_LABEL in text
    assert "do not count toward the mapping totals" in text
    assert "CMMC Level 2 assessments reference SP 800-171 Rev 2, not Rev 3" in text
    header = (REPO / "docs" / "crosswalk.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.endswith(",baselines,sp800_171r3_derived")


def test_derived_links_never_count_toward_totals() -> None:
    crosswalk, owasp = cw.load_crosswalk(), cw.load_owasp_catalog()
    authored = sum(len(f.mappings) for f in crosswalk.values())
    assert f"Mappings: {authored} total" in cw.export_markdown(crosswalk, owasp)
    document = json.loads(cw.export_json(crosswalk, owasp))
    assert len(document["mappings"]) == authored
    assert "not authored mappings" in document["derived_fields_note"]
    assert "not Rev 3" in document["derived_fields_note"]
    result = runner.invoke(app, ["crosswalk", "validate"])
    assert f"{authored} mappings" in result.stdout


def test_csv_rows_carry_derived_values() -> None:
    import csv
    import io

    crosswalk, owasp = cw.load_crosswalk(), cw.load_owasp_catalog()
    rows = list(csv.DictReader(io.StringIO(cw.export_csv(crosswalk, owasp))))
    for row in rows:
        if row["framework"] == "nist-csf-2.0":
            assert row["baselines"] == row["sp800_171r3_derived"] == ""
        else:
            assert row["baselines"] == " ".join(
                federal.baselines_for(row["framework"], row["control_id"])
            )


def test_show_prints_derived_context() -> None:
    result = runner.invoke(app, ["crosswalk", "show", "--risk", "MCP01"])
    assert result.exit_code == 0
    assert "baselines: " in result.stdout
    assert federal.SP800_171R3_LABEL in result.stdout
    assert "CMMC" in result.stdout and "not Rev 3" in result.stdout


def test_report_controls_have_additive_fields(tmp_path: Path) -> None:
    config = materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json")
    report = scan([ScanTarget(config)])
    assert report.schema_version == "1.1"
    controls = [c for f in report.findings for c in f.controls]
    for control in controls:
        assert control.baselines == federal.baselines_for(control.framework, control.control_id)
        assert control.sp800_171r3_derived == federal.sp800_171r3_for(
            control.framework, control.control_id
        )
        if control.framework == "nist-csf-2.0":
            assert control.baselines == control.sp800_171r3_derived == []
    assert any(c.baselines for c in controls)
    assert any(c.sp800_171r3_derived for c in controls)

    md = markdown.render(report)
    page = html.render(report)
    assert re.search(r"SP 800-53r5 IA-5 .*\[baselines: LOW, MODERATE, HIGH", md)
    assert "baselines: none" in md  # IA-5(7) is in no baseline
    assert "baselines: LOW, MODERATE, HIGH" in page
    assert federal.SP800_171R3_LABEL in md
    assert federal.SP800_171R3_LABEL in page
