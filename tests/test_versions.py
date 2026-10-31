"""OWASP catalog versions, risk ID migration, and ``--catalog-version`` (V02 N1).

The 2099-test catalog and migration are synthetic fixtures (tests/fixtures/catalog_versions/):
MCP07 is renumbered to MCP11, MCP08 is retired, and MCP12 is new.
"""

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import FIXTURES, materialize
from typer.testing import CliRunner

from mcp_crosswalk import crosswalk as cw
from mcp_crosswalk import resources, versions
from mcp_crosswalk.cli import app
from mcp_crosswalk.engine import ScanTarget, scan
from mcp_crosswalk.models import Migration, MigrationEntry
from mcp_crosswalk.reporters import sarif

REPO = Path(__file__).resolve().parent.parent
VERSION_FIXTURES = FIXTURES / "catalog_versions"
runner = CliRunner()


def _digest(directory: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob("*"))}


@pytest.fixture
def test_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A data root with the real crosswalk and catalogs plus the synthetic 2099-test version."""
    root = tmp_path / "data"
    shutil.copytree(REPO / "crosswalk", root / "crosswalk")
    owasp = root / "catalog" / "owasp-mcp"
    shutil.copytree(REPO / "catalog" / "owasp-mcp", owasp)
    shutil.copy(VERSION_FIXTURES / "versions.yaml", owasp / "versions.yaml")
    shutil.copy(VERSION_FIXTURES / "2099-test.yaml", owasp / "2099-test.yaml")
    shutil.copy(
        VERSION_FIXTURES / "migrations" / "2025-beta__to__2099-test.yaml",
        owasp / "migrations" / "2025-beta__to__2099-test.yaml",
    )
    (root / "catalog" / "frameworks").symlink_to(REPO / "catalog" / "frameworks")
    monkeypatch.setattr(resources, "data_root", lambda: root)
    return root


def _author_2099_crosswalk(root: Path, tmp_path: Path) -> Path:
    """Migrate, add the hand-authored MCP12 file, and install it as the 2099-test crosswalk."""
    out = tmp_path / "migrated"
    result = runner.invoke(app, ["crosswalk", "migrate", "--to", "2099-test", "--out", str(out)])
    assert result.exit_code == 1, result.output
    shutil.copy(VERSION_FIXTURES / "MCP12.yaml", out / "MCP12.yaml")
    shutil.copytree(out, root / "crosswalk-2099-test")
    return root / "crosswalk-2099-test"


# --- Shipped versions file --------------------------------------------------------------------


def test_shipped_versions_file() -> None:
    assert versions.available_versions() == ["2025-beta"]
    assert versions.default_version() == "2025-beta"
    resolved = versions.resolve(None)
    assert resolved.info.status == "beta"
    assert resolved.crosswalk_dir == resources.crosswalk_dir()
    assert versions.load_owasp().version == "2025-beta"


def test_shipped_migrations_dir_has_no_real_migration() -> None:
    # The next OWASP version is not published, so no real migration may ship.
    shipped = sorted(p.name for p in (resources.owasp_dir() / "migrations").iterdir())
    assert shipped == ["README.md"]


def test_default_translation_is_identity() -> None:
    assert versions.risk_translation() == {f"MCP{n:02d}": f"MCP{n:02d}" for n in range(1, 11)}
    assert versions.check_risk_index_for() == {
        c.id: c.risk_ids for c in versions.checks_for("2025-beta")
    }


def test_listing_includes_test_version(test_root: Path) -> None:
    assert versions.available_versions() == ["2025-beta", "2099-test"]
    assert versions.resolve("2099-test").crosswalk_dir == test_root / "crosswalk-2099-test"


# --- Unknown versions ---------------------------------------------------------------------------


def test_unknown_version_raises_with_list() -> None:
    with pytest.raises(versions.UnknownVersionError) as info:
        versions.resolve("2031")
    assert info.value.available == ["2025-beta"]
    assert "available: 2025-beta" in str(info.value)


@pytest.mark.parametrize(
    "command",
    [
        ["crosswalk", "validate"],
        ["crosswalk", "show"],
        ["crosswalk", "export", "--format", "md"],
        ["crosswalk", "migrate", "--out", "unused"],
    ],
)
def test_cli_unknown_version_exits_2(command: list[str], tmp_path: Path) -> None:
    flag = ["--to", "nope"] if "migrate" in command else ["--catalog-version", "nope"]
    result = runner.invoke(app, [*command, *flag])
    assert result.exit_code == 2
    assert "unknown OWASP catalog version 'nope'" in result.output
    assert "available: 2025-beta" in result.output


def test_scan_unknown_version_exits_2_before_writing(tmp_path: Path) -> None:
    config = materialize("generic.json", tmp_path / "generic.json")
    out = tmp_path / "o"
    args = ["scan", "--config", str(config), "--out", str(out), "--catalog-version", "nope"]
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "available: 2025-beta" in result.output
    assert not out.exists()


# --- Default behavior unchanged ----------------------------------------------------------------


def test_explicit_default_version_matches_implicit(tmp_path: Path) -> None:
    config = materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json")
    implicit = scan([ScanTarget(config)])
    explicit = scan([ScanTarget(config)], catalog_version="2025-beta")
    implicit_dump = implicit.model_dump(exclude={"generated_at"})
    assert implicit_dump == explicit.model_dump(exclude={"generated_at"})


@pytest.mark.parametrize(
    "command",
    [["crosswalk", "validate"], ["crosswalk", "show"], ["crosswalk", "export", "--format", "csv"]],
)
def test_cli_explicit_default_version(command: list[str]) -> None:
    plain = runner.invoke(app, command)
    explicit = runner.invoke(app, [*command, "--catalog-version", "2025-beta"])
    assert plain.exit_code == explicit.exit_code == 0
    assert plain.stdout == explicit.stdout


# --- Migration --------------------------------------------------------------------------------


def test_migrate_rename_retire_and_new_unmapped(test_root: Path, tmp_path: Path) -> None:
    source_before = _digest(test_root / "crosswalk")
    out = tmp_path / "migrated"
    result = runner.invoke(app, ["crosswalk", "migrate", "--to", "2099-test", "--out", str(out)])
    assert result.exit_code == 1, result.output
    assert "Renamed:       MCP07 -> MCP11" in result.stdout
    assert "Retired:       MCP08" in result.stdout
    assert "mapping(s) not carried over" in result.stdout
    assert "New, unmapped: MCP12" in result.stdout

    names = sorted(p.name for p in out.iterdir())
    expected = [f"MCP{n:02d}.yaml" for n in (1, 2, 3, 4, 5, 6, 9, 10, 11)]
    assert names == expected
    mcp11 = yaml.safe_load((out / "MCP11.yaml").read_text(encoding="utf-8"))
    original = yaml.safe_load((test_root / "crosswalk" / "MCP07.yaml").read_text("utf-8"))
    assert mcp11["risk_id"] == "MCP11"
    assert mcp11["catalog_version"] == "2099-test"
    assert mcp11["review_status"] == "draft"
    assert mcp11["mappings"] == original["mappings"]
    assert "Migrated by `mcpxw crosswalk migrate`" in (out / "MCP11.yaml").read_text("utf-8")
    # The source is untouched.
    assert _digest(test_root / "crosswalk") == source_before


def test_migrate_result_object(test_root: Path, tmp_path: Path) -> None:
    from mcp_crosswalk.migrate import migrate_crosswalk

    result = migrate_crosswalk("2099-test", tmp_path / "m")
    assert result.renamed == [("MCP07", "MCP11")]
    assert [r[0] for r in result.retired] == ["MCP08"]
    mcp08 = cw.load_crosswalk(test_root / "crosswalk")["MCP08"]
    assert result.retired[0][1] == len(mcp08.mappings)
    assert result.new_unmapped == ["MCP12"]
    assert "MCP01" in result.unchanged


def test_migrated_files_validate_against_target(test_root: Path, tmp_path: Path) -> None:
    out = tmp_path / "migrated"
    runner.invoke(app, ["crosswalk", "migrate", "--to", "2099-test", "--out", str(out)])
    owasp = versions.load_owasp("2099-test")
    index = versions.check_risk_index_for("2099-test")
    # Before the new risk is authored, the gap is a validation problem.
    problems = cw.validate_crosswalk(out, owasp=owasp, check_risks=index)
    assert problems == ["MCP12.yaml: missing crosswalk file for OWASP risk MCP12"]
    shutil.copy(VERSION_FIXTURES / "MCP12.yaml", out / "MCP12.yaml")
    assert cw.validate_crosswalk(out, owasp=owasp, check_risks=index) == []
    args = ["crosswalk", "validate", "--catalog-version", "2099-test", "--crosswalk-dir", str(out)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "OWASP catalog 2099-test" in result.stdout


def test_migrate_exit_0_when_no_new_risks(test_root: Path, tmp_path: Path) -> None:
    path = test_root / "catalog" / "owasp-mcp" / "2099-test.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["risks"] = [r for r in data["risks"] if r["short_id"] != "MCP12"]
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    out = tmp_path / "m"
    result = runner.invoke(app, ["crosswalk", "migrate", "--to", "2099-test", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "New, unmapped" not in result.stdout


@pytest.mark.parametrize("target", ["crosswalk", "crosswalk/sub", "crosswalk-2099-test"])
def test_migrate_never_writes_in_place(test_root: Path, target: str) -> None:
    before = _digest(test_root / "crosswalk")
    out = test_root / target
    result = runner.invoke(app, ["crosswalk", "migrate", "--to", "2099-test", "--out", str(out)])
    assert result.exit_code == 2
    assert "never writes in place" in result.output
    assert _digest(test_root / "crosswalk") == before
    assert not (test_root / "crosswalk" / "sub").exists()
    assert not (test_root / "crosswalk-2099-test").exists()


def test_migrate_refuses_file_and_symlink_outputs(test_root: Path, tmp_path: Path) -> None:
    a_file = tmp_path / "file.txt"
    a_file.write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(test_root / "crosswalk")
    for out in (a_file, link):
        args = ["crosswalk", "migrate", "--to", "2099-test", "--out", str(out)]
        result = runner.invoke(app, args)
        assert result.exit_code == 2, out


def test_migrate_refuses_symlinked_target_file(test_root: Path, tmp_path: Path) -> None:
    out = tmp_path / "m"
    out.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    (out / "MCP11.yaml").symlink_to(victim)
    result = runner.invoke(app, ["crosswalk", "migrate", "--to", "2099-test", "--out", str(out)])
    assert result.exit_code == 2
    assert victim.read_text(encoding="utf-8") == "keep"


def test_migrate_to_default_or_without_migration_file(test_root: Path, tmp_path: Path) -> None:
    same = runner.invoke(app, ["crosswalk", "migrate", "--to", "2025-beta", "--out", "x"])
    assert same.exit_code == 2
    assert "already the default" in same.output
    (test_root / "catalog" / "owasp-mcp" / "migrations" / "2025-beta__to__2099-test.yaml").unlink()
    missing = runner.invoke(
        app, ["crosswalk", "migrate", "--to", "2099-test", "--out", str(tmp_path / "m")]
    )
    assert missing.exit_code == 2
    assert "no migration file" in missing.output


# --- Migration file validation ---------------------------------------------------------------


def _migration(**changes: object) -> Migration:
    mapping = {
        f"MCP{n:02d}": MigrationEntry(to=f"MCP{n:02d}", note="Unchanged.") for n in range(1, 11)
    }
    mapping["MCP07"] = MigrationEntry(to="MCP11", note="Renumbered.")
    mapping["MCP08"] = MigrationEntry(to=None, note="Retired.")
    data: dict[str, object] = {
        "from_version": "2025-beta",
        "to_version": "2099-test",
        "map": mapping,
    }
    data.update(changes)
    return Migration.model_validate(data)


def test_migration_problems(test_root: Path) -> None:
    source, target = versions.load_owasp("2025-beta"), versions.load_owasp("2099-test")
    assert versions.migration_problems(_migration(), source, target) == []

    bad = _migration()
    del bad.map["MCP03"]
    bad.map["MCP99"] = MigrationEntry(to="MCP03", note="x")
    bad.map["MCP04"] = MigrationEntry(to="MCP77", note="x")
    bad.map["MCP05"] = MigrationEntry(to="MCP06", note="x")
    problems = versions.migration_problems(bad, source, target)
    assert any("no entry for MCP03" in p for p in problems)
    assert any("MCP99 is not a risk in 2025-beta" in p for p in problems)
    assert any("MCP77 is not a risk in 2099-test" in p for p in problems)
    assert any("both map to MCP06" in p for p in problems)

    swapped = _migration(from_version="2099-test", to_version="2025-beta")
    problems = versions.migration_problems(swapped, source, target)
    assert any("from_version" in p for p in problems)
    assert any("to_version" in p for p in problems)


def test_invalid_migration_file_is_reported(test_root: Path) -> None:
    path = test_root / "catalog" / "owasp-mcp" / "migrations" / "2025-beta__to__2099-test.yaml"
    path.write_text("from_version: 2025-beta\nto_version: 2099-test\nmap: {}\n", encoding="utf-8")
    with pytest.raises(versions.VersionError, match="no entry for MCP01"):
        versions.load_migration("2025-beta", "2099-test")
    path.write_text("from_version: [\n", encoding="utf-8")
    with pytest.raises(versions.VersionError, match="cannot read"):
        versions.load_migration("2025-beta", "2099-test")
    path.write_text("from_version: 1\nsurprise: true\n", encoding="utf-8")
    with pytest.raises(versions.VersionError, match="is invalid"):
        versions.load_migration("2025-beta", "2099-test")


def test_migration_schema_matches_fixture() -> None:
    import jsonschema

    schema = json.loads((REPO / "schema" / "migration.schema.json").read_text("utf-8"))
    path = VERSION_FIXTURES / "migrations" / "2025-beta__to__2099-test.yaml"
    jsonschema.validate(yaml.safe_load(path.read_text(encoding="utf-8")), schema)
    versions_schema = json.loads((REPO / "schema" / "versions.schema.json").read_text("utf-8"))
    for file in (
        REPO / "catalog" / "owasp-mcp" / "versions.yaml",
        VERSION_FIXTURES / "versions.yaml",
    ):
        jsonschema.validate(yaml.safe_load(file.read_text(encoding="utf-8")), versions_schema)


# --- Versions file validation ----------------------------------------------------------------


def _write_versions(root: Path, text: str) -> None:
    (root / "catalog" / "owasp-mcp" / "versions.yaml").write_text(text, encoding="utf-8")


def test_versions_file_errors(test_root: Path) -> None:
    entry = "  - {id: 2025-beta, file: 2025-beta.yaml, status: beta, retrieved: x}\n"
    _write_versions(test_root, "default: 2025-beta\nversions:\n" + entry + entry)
    with pytest.raises(versions.VersionError, match="more than once"):
        versions.load_versions()
    _write_versions(test_root, "default: other\nversions:\n" + entry)
    with pytest.raises(versions.VersionError, match="is not listed"):
        versions.load_versions()
    _write_versions(test_root, "default: 2025-beta\nversions: [{id: '../x'}]\n")
    with pytest.raises(versions.VersionError, match="invalid"):
        versions.load_versions()
    _write_versions(test_root, "default: [\n")
    with pytest.raises(versions.VersionError, match="cannot read"):
        versions.load_versions()


def test_catalog_version_must_match_versions_id(test_root: Path) -> None:
    path = test_root / "catalog" / "owasp-mcp" / "2099-test.yaml"
    path.write_text(path.read_text("utf-8").replace('"2099-test"', '"2099-other"'), "utf-8")
    with pytest.raises(versions.VersionError, match="does not match"):
        versions.load_owasp("2099-test")
    path.write_text("version: x\n", encoding="utf-8")
    with pytest.raises(versions.VersionError, match="is invalid"):
        versions.load_owasp("2099-test")


def test_translation_without_migration_file(test_root: Path) -> None:
    owasp = test_root / "catalog" / "owasp-mcp"
    (owasp / "migrations" / "2025-beta__to__2099-test.yaml").unlink()
    with pytest.raises(versions.VersionError, match="MCP07, MCP08 do not exist"):
        versions.risk_translation("2099-test")
    # A version with the same IDs needs no migration file: IDs carry over unchanged.
    text = (owasp / "2025-beta.yaml").read_text("utf-8").replace('"2025-beta"', '"2025-final"')
    (owasp / "2025-final.yaml").write_text(text, encoding="utf-8")
    listing = (owasp / "versions.yaml").read_text("utf-8")
    extra = "  - {id: 2025-final, file: 2025-final.yaml, status: final, retrieved: x}\n"
    (owasp / "versions.yaml").write_text(listing + extra, encoding="utf-8")
    assert versions.risk_translation("2025-final")["MCP07"] == "MCP07"


# --- Commands with a non-default version ------------------------------------------------------


def test_checks_translated_for_target(test_root: Path) -> None:
    index = versions.check_risk_index_for("2099-test")
    assert index["MCPXW-007"] == ("MCP11",)
    assert index["MCPXW-006"] == ("MCP02", "MCP10")


def test_scan_with_test_version(test_root: Path, tmp_path: Path) -> None:
    _author_2099_crosswalk(test_root, tmp_path)
    config = materialize("kitchen_sink.json", tmp_path / "kitchen_sink.json")
    report = scan([ScanTarget(config)], catalog_version="2099-test")
    assert report.catalog.owasp_version == "2099-test"
    coverage = {row.risk_id: row for row in report.coverage}
    assert "MCP07" not in coverage
    assert "MCP08" not in coverage
    assert coverage["MCP11"].status == "Assessed (static)"
    assert coverage["MCP12"].status == "Not assessed (requires active analysis)"
    f007 = [f for f in report.findings if f.check_id == "MCPXW-007"]
    assert f007
    assert all(f.risk_ids == ["MCP11"] for f in f007)
    assert all(c.risk_id == "MCP11" for f in f007 for c in f.controls)
    assert all(f.controls for f in f007)
    sarif_doc = json.loads(sarif.render(report))
    rule = next(
        r for r in sarif_doc["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "MCPXW-007"
    )
    assert "MCP11" in rule["properties"]["tags"]
    assert "MCP07" not in rule["properties"]["tags"]

    out = tmp_path / "o"
    args = ["scan", "--config", str(config), "--out", str(out), "--catalog-version", "2099-test"]
    result = runner.invoke(app, [*args, "--fail-on", "none"])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "mcpxw-report.json").read_text(encoding="utf-8"))
    assert data["catalog"]["owasp_version"] == "2099-test"


def test_show_export_validate_with_test_version(test_root: Path, tmp_path: Path) -> None:
    _author_2099_crosswalk(test_root, tmp_path)
    flag = ["--catalog-version", "2099-test"]
    show = runner.invoke(app, ["crosswalk", "show", "--risk", "MCP11", *flag])
    assert show.exit_code == 0, show.output
    assert "MCP11: Insufficient Authentication & Authorization" in show.stdout
    export = runner.invoke(app, ["crosswalk", "export", "--format", "md", *flag])
    assert export.exit_code == 0
    assert "`2099-test`" in export.stdout
    assert "Scanner checks: MCPXW-007, MCPXW-008" in export.stdout
    validate = runner.invoke(app, ["crosswalk", "validate", *flag])
    assert validate.exit_code == 0, validate.output


def test_version_without_crosswalk(test_root: Path, tmp_path: Path) -> None:
    listing = test_root / "catalog" / "owasp-mcp" / "versions.yaml"
    listing.write_text(
        listing.read_text("utf-8").replace("crosswalk: crosswalk-2099-test", "crosswalk: null"),
        encoding="utf-8",
    )
    flag = ["--catalog-version", "2099-test"]
    for command in (["crosswalk", "show"], ["crosswalk", "export", "--format", "md"]):
        result = runner.invoke(app, [*command, *flag])
        assert result.exit_code == 2
        assert "no crosswalk has been authored" in result.output
    validate = runner.invoke(app, ["crosswalk", "validate", *flag])
    assert validate.exit_code == 2
    assert "--crosswalk-dir" in validate.output
    config = materialize("generic.json", tmp_path / "generic.json")
    scan_result = runner.invoke(
        app, ["scan", "--config", str(config), "--out", str(tmp_path / "o"), *flag]
    )
    assert scan_result.exit_code == 2


# --- Independent review regressions (N8) --------------------------------------------------------


def _migrate(out: Path) -> Any:
    return runner.invoke(app, ["crosswalk", "migrate", "--to", "2099-test", "--out", str(out)])


def test_r6_identity_check_catches_case_variants(
    test_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Emulate a case-insensitive file system (macOS default): resolve() keeps the letter case the
    # caller typed, so only a file-identity comparison sees that CROSSWALK is crosswalk.
    import os

    from mcp_crosswalk import migrate

    real_samefile = os.path.samefile

    def case_insensitive_samefile(a: Any, b: Any) -> bool:
        if str(a).lower() == str(b).lower():
            return True
        return real_samefile(a, b)

    monkeypatch.setattr(os.path, "samefile", case_insensitive_samefile)
    upper = test_root / "CROSSWALK"
    upper.mkdir()  # on a case-insensitive file system this would be the same directory
    assert migrate._same_or_inside(upper / "sub", test_root / "crosswalk")
    result = _migrate(upper)
    assert result.exit_code == 2
    assert "never writes in place" in result.output


def test_r7_every_configured_crosswalk_and_catalog_are_protected(
    test_root: Path,
) -> None:
    listing = test_root / "catalog" / "owasp-mcp" / "versions.yaml"
    extra = (
        "  - {id: 2025-final, file: 2025-final.yaml, status: final, retrieved: x, "
        "crosswalk: crosswalk-final}\n"
    )
    listing.write_text(listing.read_text("utf-8") + extra, encoding="utf-8")
    (test_root / "crosswalk-final").mkdir()
    for target in (test_root / "crosswalk-final", test_root / "catalog" / "migrated"):
        result = _migrate(target)
        assert result.exit_code == 2, target
        assert "never writes in place" in result.output
    assert list((test_root / "crosswalk-final").iterdir()) == []
    assert not (test_root / "catalog" / "migrated").exists()


def test_r13_validate_missing_crosswalk_dir_exits_2(tmp_path: Path) -> None:
    args = ["crosswalk", "validate", "--crosswalk-dir", str(tmp_path / "nope")]
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "does not exist" in result.output
