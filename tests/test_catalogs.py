from pathlib import Path

import pytest
import yaml

from mcp_crosswalk import catalogs
from mcp_crosswalk.models import OwaspCatalog
from mcp_crosswalk.resources import owasp_catalog_path

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("framework", "control_id", "expected_id"),
    [
        ("nist-800-53r5", "AC-2", "AC-2"),
        ("nist-800-53r5", "AC-2(1)", "AC-2(1)"),
        ("nist-800-53r5", "IA-5(7)", "IA-5(7)"),
        ("nist-csf-2.0", "GV.OC-01", "GV.OC-01"),
        ("nist-csf-2.0", "PR.AA-01", "PR.AA-01"),
    ],
)
def test_known_ids_resolve(framework: str, control_id: str, expected_id: str) -> None:
    entry = catalogs.lookup(framework, control_id)
    assert entry is not None
    assert entry.id == expected_id
    assert entry.title
    assert entry.statement
    assert not entry.withdrawn


@pytest.mark.parametrize("control_id", ["ac-2.1", "ac-2(1)", "AC-02(01)", " ac-2.1 "])
def test_lowercase_and_oscal_forms_work(control_id: str) -> None:
    entry = catalogs.lookup("nist-800-53r5", control_id)
    assert entry is not None
    assert entry.id == "AC-2(1)"
    assert entry.oscal_id == "ac-2.1"


def test_csf_lowercase_input() -> None:
    entry = catalogs.lookup("nist-csf-2.0", "pr.aa-01")
    assert entry is not None
    assert entry.id == "PR.AA-01"


def test_enhancement_title_includes_base_title() -> None:
    entry = catalogs.lookup("nist-800-53r5", "IA-5(7)")
    assert entry is not None
    assert entry.title.startswith("Authenticator Management | ")


def test_statement_renders_parameters() -> None:
    entry = catalogs.lookup("nist-800-53r5", "AC-2")
    assert entry is not None
    assert "{{" not in entry.statement
    assert "[Assignment:" in entry.statement or "[Selection" in entry.statement


def test_withdrawn_control_reported_as_withdrawn() -> None:
    entry = catalogs.lookup("nist-800-53r5", "AC-2(10)")
    assert entry is not None
    assert entry.withdrawn


@pytest.mark.parametrize(
    ("framework", "control_id"),
    [
        ("nist-800-53r5", "ZZ-99"),
        ("nist-800-53r5", "AC-2(999)"),
        ("nist-800-53r5", "not an id"),
        ("nist-csf-2.0", "GV.OC"),  # a category, not a subcategory
        ("nist-csf-2.0", "XX.YY-01"),
        ("unknown-framework", "AC-2"),
    ],
)
def test_unknown_ids_return_none(framework: str, control_id: str) -> None:
    assert catalogs.lookup(framework, control_id) is None


def test_display_and_normalize_roundtrip() -> None:
    assert catalogs.display_id("nist-800-53r5", "cm-7.5") == "CM-7(5)"
    assert catalogs.normalize_id("nist-800-53r5", "CM-7(5)") == "cm-7.5"
    assert catalogs.normalize_id("nist-csf-2.0", "gv.sc-05") == "GV.SC-05"
    assert catalogs.normalize_id("other", "x") is None


def test_catalog_metadata_and_hash() -> None:
    catalog = catalogs.load_catalog("nist-800-53r5")
    assert len(catalog.source_sha256) == 64
    assert "800-53" in catalog.title
    assert len(catalog.entries) > 1000
    csf = catalogs.load_catalog("nist-csf-2.0")
    assert all(key.count(".") == 1 and "-" in key for key in csf.entries)


def test_sources_md_lists_hashes_of_vendored_files() -> None:
    sources = (catalogs.frameworks_dir() / "SOURCES.md").read_text(encoding="utf-8")
    for framework in catalogs.FRAMEWORKS:
        assert catalogs.load_catalog(framework).source_sha256 in sources


def test_minimal_fixture_catalog_parses() -> None:
    catalog = catalogs.load_catalog_file("nist-800-53r5", FIXTURES / "oscal_minimal_800_53.json")
    assert set(catalog.entries) == {"ac-1", "ac-1.1", "ac-2"}
    withdrawn = catalog.lookup("AC-1(1)")
    assert withdrawn is not None
    assert withdrawn.withdrawn
    ac2 = catalog.lookup("ac-2")
    assert ac2 is not None
    assert "[Selection (one): alpha; beta]" in ac2.statement


def test_load_catalog_rejects_unknown_framework() -> None:
    with pytest.raises(KeyError):
        catalogs.load_catalog("bogus")


def test_owasp_catalog_has_ten_risks() -> None:
    data = yaml.safe_load(owasp_catalog_path().read_text(encoding="utf-8"))
    catalog = OwaspCatalog.model_validate(data)
    assert catalog.version == "2025-beta"
    assert [r.short_id for r in catalog.risks] == [f"MCP{n:02d}" for n in range(1, 11)]
    assert catalog.by_short_id()["MCP06"].aliases == ["Intent Flow Subversion"]
    for risk in catalog.risks:
        assert risk.id == f"{risk.short_id}:2025"
        assert risk.summary.count(". ") <= 2  # at most 3 sentences
