"""``mcpxw enrich`` on synthetic SARIF fixtures (V02 N5). No third-party scanner is used."""

import builtins
import copy
import io
import json
import shutil
import socket
import urllib.request
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from typer.testing import CliRunner

from mcp_crosswalk import crosswalk as cw
from mcp_crosswalk import enrich
from mcp_crosswalk.cli import app
from mcp_crosswalk.models import DISCLAIMER

FIXTURES = Path(__file__).parent / "fixtures" / "sarif"
SARIF_SCHEMA = Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json"
runner = CliRunner()


def _copy(name: str, tmp_path: Path) -> Path:
    target = tmp_path / "in" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / name, target)
    return target


def _run(name: str, tmp_path: Path, *extra: str) -> tuple[Any, Path, Path]:
    source = _copy(name, tmp_path)
    out = tmp_path / "out"
    result = runner.invoke(app, ["enrich", str(source), "--out", str(out), *extra])
    return result, source, out


def _enriched(out: Path, source: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((out / f"{source.stem}.enriched.sarif").read_text("utf-8"))
    return data


def _results(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for run in document["runs"] for r in run.get("results", [])]


def _strip(enriched: dict[str, Any], original: dict[str, Any]) -> dict[str, Any]:
    """Remove exactly what enrich adds, so the rest can be compared with the input."""
    stripped = copy.deepcopy(enriched)
    pairs = zip(_results(stripped), _results(original), strict=True)
    for new, old in pairs:
        props = new.get("properties")
        if not isinstance(props, dict) or enrich.PROPERTY_KEY not in props:
            continue
        del props[enrich.PROPERTY_KEY]
        old_props = old.get("properties", {})
        old_tags = old_props.get("tags") if isinstance(old_props, dict) else None
        if isinstance(props.get("tags"), list):
            if old_tags is None:
                del props["tags"]
            else:
                props["tags"] = props["tags"][: len(old_tags)]
        if "properties" not in old and not props:
            del new["properties"]
    return stripped


def _mapping_count(risk_ids: list[str]) -> int:
    crosswalk = cw.load_crosswalk()
    return sum(len(crosswalk[r].mappings) for r in risk_ids)


ALL_VALID = [
    "rule_id.sarif",
    "rule_tags.sarif",
    "message_suffix.sarif",
    "no_mcp_ids.sarif",
    "multi_run_extensions.sarif",
    "hostile.sarif",
]


# --- ID extraction ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("MCP01", {"MCP01"}),
        ("mcp10", {"MCP10"}),
        ("see MCP07:2025.", {"MCP07"}),
        ("(MCP04), MCP05;", {"MCP04", "MCP05"}),
        ("owasp-mcp-top-10/mcp04", {"MCP04"}),
        ("MCP01 and MCP01:2025", {"MCP01"}),
        ("MCP011", set()),
        ("XMCP01", set()),
        ("MCP01a", set()),
        ("MCP_01", set()),
        ("MCP 01", set()),
        ("MCP1", set()),
        ("MCP00", set()),
        ("MCP11", set()),
        ("mcp-1.0.1", set()),
        ("version 2.1.0 of mcp-server-fetch", set()),
        ("MCP07:1999", set()),
        ("MCP07: Insufficient Authentication", {"MCP07"}),
        ("MCP07:2025/MCP08:2026", {"MCP07", "MCP08"}),
        ("MCP07:2025x", set()),
    ],
)
def test_find_ids(text: str, expected: set[str]) -> None:
    assert enrich.find_ids(text) == expected


def test_find_ids_non_string() -> None:
    assert enrich.find_ids(None) == set()
    assert enrich.find_ids(["MCP01"]) == set()


# --- Fixture shapes -----------------------------------------------------------------------------


def test_ids_in_rule_id(tmp_path: Path) -> None:
    result, source, out = _run("rule_id.sarif", tmp_path)
    assert result.exit_code == 0, result.output
    results = _results(_enriched(out, source))
    added = results[0]["properties"][enrich.PROPERTY_KEY]
    assert added["risk_ids"] == ["MCP01"]
    assert added["catalog_version"] == "2025-beta"
    assert added["disclaimer"] == DISCLAIMER
    assert len(added["controls"]) == _mapping_count(["MCP01"])
    ia57 = next(c for c in added["controls"] if c["control_id"] == "IA-5(7)")
    assert ia57 == {
        "risk_id": "MCP01",
        "framework": "nist-800-53r5",
        "control_id": "IA-5(7)",
        "title": ia57["title"],
        "relationship": ia57["relationship"],
        "confidence": ia57["confidence"],
        "baselines": [],
    }
    assert "No Embedded Unencrypted Static Authenticators" in ia57["title"]
    ia5 = next(c for c in added["controls"] if c["control_id"] == "IA-5")
    assert ia5["baselines"] == ["LOW", "MODERATE", "HIGH"]
    tags = results[0]["properties"]["tags"]
    assert tags[:2] == ["security", "nist-800-53r5/IA-5"]
    assert "nist-800-53r5/IA-5(7)" in tags
    assert "nist-csf-2.0/PR.AA-01" in tags
    assert tags.count("nist-800-53r5/IA-5") == 1  # existing tag not duplicated
    assert len(tags) == len(set(tags))
    # The false-positive message in the second result does not trigger enrichment.
    assert "properties" not in results[1]


def test_ids_only_in_rule_properties_tags(tmp_path: Path) -> None:
    result, source, out = _run("rule_tags.sarif", tmp_path)
    assert result.exit_code == 0, result.output
    results = _results(_enriched(out, source))
    for item in results:  # first by ruleId, second by ruleIndex only
        assert item["properties"][enrich.PROPERTY_KEY]["risk_ids"] == ["MCP04"]
        assert "nist-800-53r5/CM-7(5)" in item["properties"]["tags"]


def test_ids_only_in_message_with_year_suffix(tmp_path: Path) -> None:
    result, source, out = _run("message_suffix.sarif", tmp_path)
    assert result.exit_code == 0, result.output
    item = _results(_enriched(out, source))[0]
    added = item["properties"][enrich.PROPERTY_KEY]
    assert added["risk_ids"] == ["MCP02", "MCP07"]
    assert len(added["controls"]) == _mapping_count(["MCP02", "MCP07"])
    assert {c["risk_id"] for c in added["controls"]} == {"MCP02", "MCP07"}


def test_results_without_ids_are_untouched(tmp_path: Path) -> None:
    result, source, out = _run("no_mcp_ids.sarif", tmp_path, "--format", "sarif,json")
    assert result.exit_code == 0, result.output
    original = json.loads(source.read_text("utf-8"))
    assert _enriched(out, source) == original
    summary = json.loads((out / enrich.SUMMARY_JSON).read_text("utf-8"))
    assert (summary["total_results"], summary["enriched"], summary["not_enriched"]) == (2, 0, 2)


def test_multiple_runs_and_extensions(tmp_path: Path) -> None:
    result, source, out = _run("multi_run_extensions.sarif", tmp_path, "--format", "sarif,json")
    assert result.exit_code == 0, result.output
    results = _results(_enriched(out, source))
    risk = [r.get("properties", {}).get(enrich.PROPERTY_KEY, {}).get("risk_ids") for r in results]
    assert risk == [["MCP09"], ["MCP10"], None, ["MCP05"]]
    summary = json.loads((out / enrich.SUMMARY_JSON).read_text("utf-8"))
    assert summary["runs"] == 3
    assert summary["total_results"] == 4
    assert summary["enriched"] == 3
    assert summary["not_enriched"] == 1
    assert summary["per_risk"] == {"MCP05": 1, "MCP09": 1, "MCP10": 1}


def test_hostile_strings_preserved_not_executed(tmp_path: Path) -> None:
    result, source, out = _run("hostile.sarif", tmp_path, "--format", "sarif,json,md")
    assert result.exit_code == 0, result.output
    original = json.loads(source.read_text("utf-8"))
    enriched = _enriched(out, source)
    assert _strip(enriched, original) == original
    item = _results(enriched)[0]
    assert item["properties"][enrich.PROPERTY_KEY]["risk_ids"] == ["MCP03", "MCP06"]
    assert item["properties"]["tags"][:3] == original["runs"][0]["results"][0]["properties"]["tags"]
    assert item["properties"]["tags"].count("nist-800-53r5/SI-10") == 1
    md = (out / enrich.SUMMARY_MD).read_text("utf-8")
    for text in (md, result.output):
        assert "<script>" not in text
        assert "onerror" not in text
        assert "HYPERLINK" not in text


def test_non_list_tags_and_non_object_properties_are_left_alone() -> None:
    document: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "t"}},
                "results": [
                    {"ruleId": "MCP01", "message": {"text": "x"}, "properties": {"tags": "s"}},
                    {"ruleId": "MCP01", "message": {"text": "x"}, "properties": "odd"},
                ],
            }
        ],
    }
    summary = enrich.enrich_document(document)
    first, second = document["runs"][0]["results"]
    assert first["properties"]["tags"] == "s"
    assert first["properties"][enrich.PROPERTY_KEY]["risk_ids"] == ["MCP01"]
    assert second["properties"] == "odd"
    assert (summary.enriched, summary.not_enriched) == (1, 1)


# --- Round trip, schema, summary ---------------------------------------------------------------


@pytest.mark.parametrize("name", ALL_VALID)
def test_round_trip_preserves_everything_else(name: str, tmp_path: Path) -> None:
    result, source, out = _run(name, tmp_path)
    assert result.exit_code == 0, result.output
    original = json.loads(source.read_text("utf-8"))
    assert _strip(_enriched(out, source), original) == original


@pytest.mark.parametrize("name", ALL_VALID)
def test_enriched_sarif_validates_against_official_schema(name: str, tmp_path: Path) -> None:
    schema = json.loads(SARIF_SCHEMA.read_text("utf-8"))
    result, source, out = _run(name, tmp_path)
    assert result.exit_code == 0
    jsonschema.validate(json.loads(source.read_text("utf-8")), schema)  # fixtures are valid SARIF
    jsonschema.validate(_enriched(out, source), schema)


def test_summary_files_and_id_scheme_caution(tmp_path: Path) -> None:
    result, _, out = _run("rule_id.sarif", tmp_path, "--format", "json,md")
    assert result.exit_code == 0, result.output
    assert sorted(p.name for p in out.iterdir()) == [enrich.SUMMARY_JSON, enrich.SUMMARY_MD]
    summary = json.loads((out / enrich.SUMMARY_JSON).read_text("utf-8"))
    assert summary["input"] == "rule_id.sarif"
    assert summary["catalog_version"] == "2025-beta"
    assert (summary["total_results"], summary["enriched"], summary["not_enriched"]) == (2, 1, 1)
    assert summary["per_risk"] == {"MCP01": 1}
    assert summary["disclaimer"] == DISCLAIMER
    assert "official OWASP MCP Top 10 numbering" in summary["id_scheme_note"]
    md = (out / enrich.SUMMARY_MD).read_text("utf-8")
    assert "official OWASP MCP Top 10 numbering" in md
    assert DISCLAIMER in md
    assert "| MCP01 | 1 |" in md
    assert "official OWASP MCP Top 10 numbering" in result.output


def test_default_format_is_sarif_only(tmp_path: Path) -> None:
    result, source, out = _run("rule_id.sarif", tmp_path)
    assert result.exit_code == 0
    assert sorted(p.name for p in out.iterdir()) == ["rule_id.enriched.sarif"]
    assert source.read_bytes() == (FIXTURES / "rule_id.sarif").read_bytes()  # input untouched


def test_ids_without_crosswalk_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    document: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t"}}, "results": [{"ruleId": "MCP08"}]}],
    }
    crosswalk = cw.load_crosswalk()
    del crosswalk["MCP08"]
    # Simulate a catalog version whose crosswalk lacks MCP08 (for example, a retired risk).
    monkeypatch.setattr(enrich, "load_version_crosswalk", lambda _v: crosswalk)
    summary = enrich.enrich_document(document)
    assert summary.unmapped_ids == {"MCP08": 1}
    assert summary.not_enriched == 1
    assert "MCP08 (1)" in enrich.render_summary_markdown(summary)


# --- Bad input and exit codes ------------------------------------------------------------------


def _bad(tmp_path: Path, content: bytes, name: str = "bad.sarif") -> Any:
    path = tmp_path / name
    path.write_bytes(content)
    return runner.invoke(app, ["enrich", str(path), "--out", str(tmp_path / "out")])


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ((FIXTURES / "malformed.sarif").read_bytes(), "not valid JSON"),
        (b"[]", "not a SARIF 2.1.0 log"),
        (b'{"version": "2.0.0", "runs": []}', "not a SARIF 2.1.0 log"),
        (b'{"version": "2.1.0"}', '"runs" must be a list'),
        (b'{"version": "2.1.0", "runs": [1]}', '"runs" must be a list'),
        (b'{"version": "2.1.0", "runs": [{"results": {}}]}', '"results" must be objects'),
        (b'{"version": "2.1.0", "version": "2.1.0", "runs": []}', "duplicate JSON object key"),
        (b'{"version": "2.1.0", "runs": [], "x": NaN}', "non-standard JSON constant"),
        (b'{"version": "2.1.0", "runs": [], "x": ' + b"9" * 5000 + b"}", "invalid JSON value"),
        (b"[" * 100000 + b"]" * 100000, "nesting is too deep"),
        (b"\xff\xfe\x00junk", "not UTF-8"),
    ],
)
def test_bad_input_exits_2_without_traceback(tmp_path: Path, content: bytes, message: str) -> None:
    result = _bad(tmp_path, content)
    assert result.exit_code == 2, result.output
    assert message in result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / "out").exists()


def test_missing_input_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["enrich", str(tmp_path / "nope.sarif")])
    assert result.exit_code == 2
    assert "is not a file" in result.output


def test_oversized_input_exits_2(tmp_path: Path) -> None:
    path = tmp_path / "big.sarif"
    with path.open("wb") as handle:
        handle.truncate(enrich.MAX_SARIF_BYTES + 1)  # sparse file: fast, no real 50 MB write
    result = runner.invoke(app, ["enrich", str(path), "--out", str(tmp_path / "out")])
    assert result.exit_code == 2
    assert "larger than" in result.output


def test_input_growing_past_cap_while_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _copy("rule_id.sarif", tmp_path)
    monkeypatch.setattr(enrich, "MAX_SARIF_BYTES", 10)
    monkeypatch.setattr(
        Path, "stat", lambda self: type("S", (), {"st_size": 1, "st_mode": 0o100644})()
    )
    with pytest.raises(enrich.EnrichInputError, match="larger than"):
        enrich.load_sarif(path)


def test_unknown_format_and_version_exit_2(tmp_path: Path) -> None:
    source = _copy("rule_id.sarif", tmp_path)
    bad_format = runner.invoke(app, ["enrich", str(source), "--format", "pdf"])
    assert bad_format.exit_code == 2
    assert "unknown format" in bad_format.output
    bad_version = runner.invoke(app, ["enrich", str(source), "--catalog-version", "nope"])
    assert bad_version.exit_code == 2
    assert "available: 2025-beta" in bad_version.output


def test_output_safety(tmp_path: Path) -> None:
    source = _copy("rule_id.sarif", tmp_path)
    a_file = tmp_path / "file"
    a_file.write_text("x", encoding="utf-8")
    assert runner.invoke(app, ["enrich", str(source), "--out", str(a_file)]).exit_code == 2
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    (out / "rule_id.enriched.sarif").symlink_to(victim)
    assert runner.invoke(app, ["enrich", str(source), "--out", str(out)]).exit_code == 2
    assert victim.read_text(encoding="utf-8") == "keep"


def test_never_overwrites_input(tmp_path: Path) -> None:
    source = tmp_path / "x.enriched.sarif"
    shutil.copy(FIXTURES / "rule_id.sarif", source)
    with pytest.raises(enrich.EnrichInputError, match="overwrite the input"):
        enrich.write_outputs(tmp_path, {"x.enriched.sarif": "{}"}, source)


def test_unexpected_error_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _copy("rule_id.sarif", tmp_path)

    def boom(*_a: Any, **_k: Any) -> Any:
        raise KeyError("secret-ish detail")

    monkeypatch.setattr(enrich, "enrich_document", boom)
    result = runner.invoke(app, ["enrich", str(source), "--out", str(tmp_path / "o")])
    assert result.exit_code == 2
    assert "unexpected internal error (KeyError)" in result.output
    assert "secret-ish" not in result.output


# --- Offline, no URI fetching ------------------------------------------------------------------


class NetworkUsedError(AssertionError):
    pass


def test_offline_and_never_fetches_or_reads_uris(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise NetworkUsedError("network access attempted")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(urllib.request, "urlopen", refuse)

    opened: list[str] = []
    real_open = builtins.open

    def recording_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    monkeypatch.setattr(io, "open", recording_open)

    for name in ("hostile.sarif", "rule_id.sarif"):
        result, _, _ = _run(name, tmp_path / name, "--format", "sarif,json,md")
        assert not isinstance(result.exception, NetworkUsedError)
        assert result.exit_code == 0, result.output
    assert not [p for p in opened if "never-read" in p or "passwd" in p or "attacker" in p]


# --- Independent review regressions (N8) --------------------------------------------------------


def _doc(results: list[dict[str, Any]], tool: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{"tool": tool or {"driver": {"name": "t"}}, "results": results}],
    }


@pytest.mark.parametrize("number", [b"1e400", b"-1e400"])
def test_r1_non_finite_numbers_are_rejected(tmp_path: Path, number: bytes) -> None:
    result = _bad(tmp_path, b'{"version": "2.1.0", "runs": [], "rank": ' + number + b"}")
    assert result.exit_code == 2
    assert "too large to represent" in result.output
    assert not (tmp_path / "out").exists()


def test_r1_output_is_always_strict_json(tmp_path: Path) -> None:
    source = tmp_path / "f.sarif"
    source.write_text(json.dumps(_doc([{"ruleId": "MCP01", "properties": {"rank": 1.5e300}}])))
    out = tmp_path / "out"
    assert runner.invoke(app, ["enrich", str(source), "--out", str(out)]).exit_code == 0
    text = (out / "f.enriched.sarif").read_text("utf-8")
    json.loads(text, parse_constant=lambda name: pytest.fail(f"non-JSON constant {name}"))


def test_r4_rule_ids_are_scoped_to_the_owning_component() -> None:
    tool = {
        "driver": {"name": "t", "rules": [{"id": "R1", "name": "Plain"}]},
        "extensions": [{"name": "ext", "rules": [{"id": "R1", "properties": {"tags": ["MCP05"]}}]}],
    }
    document = _doc([{"ruleId": "R1", "message": {"text": "x"}}], tool)
    run = document["runs"][0]
    assert enrich.result_risk_ids(run, run["results"][0]) == set()
    in_extension = {"ruleId": "R1", "rule": {"id": "R1", "toolComponent": {"index": 0}}}
    assert enrich.result_risk_ids(run, in_extension) == {"MCP05"}


def test_r4_rule_index_follows_tool_component() -> None:
    tool = {
        "driver": {"name": "t", "rules": [{"id": "D0", "properties": {"tags": ["MCP09"]}}]},
        "extensions": [{"name": "ext", "rules": [{"id": "E0", "name": "Plain"}]}],
    }
    result = {"ruleIndex": 0, "rule": {"index": 0, "toolComponent": {"index": 0}}}
    run = _doc([result], tool)["runs"][0]
    assert enrich.result_risk_ids(run, result) == set()
    assert enrich.result_risk_ids(run, {"ruleIndex": 0}) == {"MCP09"}
    out_of_range = {"rule": {"index": 0, "toolComponent": {"index": 7}}}
    assert enrich.result_risk_ids(run, out_of_range) == set()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("connect to mcp05.internal.example.com", set()),
        ("found in servers/mcp01/config.json", set()),
        ("package mcp-server-mcp03 is unpinned", set()),
        ("see MCP10.2 for details", set()),
        ("Risk MCP07.", {"MCP07"}),
        ("(MCP07:2025) and MCP02", {"MCP02", "MCP07"}),
        ("mcp04: unpinned package", {"MCP04"}),
    ],
)
def test_r5_message_text_is_stricter(text: str, expected: set[str]) -> None:
    assert enrich.find_message_ids(text) == expected
    run = _doc([])["runs"][0]
    assert enrich.result_risk_ids(run, {"message": {"text": text}}) == expected


def test_r5_tags_and_rules_keep_the_general_pattern() -> None:
    assert enrich.find_ids("owasp-mcp-top-10/mcp04") == {"MCP04"}
    assert enrich.find_message_ids("owasp-mcp-top-10/mcp04") == set()


def test_r8_large_input_is_linear(tmp_path: Path) -> None:
    import time

    rules = [{"id": f"R{i}", "name": "Rule"} for i in range(5000)]
    rules[4999]["properties"] = {"tags": ["MCP01"]}
    results = [{"ruleId": f"R{i % 5000}", "message": {"text": "x"}} for i in range(20000)]
    document = _doc(results, {"driver": {"name": "t", "rules": rules}})
    started = time.perf_counter()
    summary = enrich.enrich_document(document)
    elapsed = time.perf_counter() - started
    assert (summary.enriched, summary.no_id) == (4, 19996)
    assert elapsed < 3.0, elapsed  # was about 4 s before the per-run rule index


def test_r9_unpaired_surrogate_writes_nothing(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    previous = out / "s.enriched.sarif"
    previous.write_text("previous good output", encoding="utf-8")
    source = tmp_path / "s.sarif"
    source.write_bytes(b'{"version": "2.1.0", "runs": [], "x": "\\ud800"}')
    result = runner.invoke(
        app, ["enrich", str(source), "--out", str(out), "--format", "json,sarif"]
    )
    assert result.exit_code == 2
    assert "not valid UTF-8" in result.output
    assert previous.read_text(encoding="utf-8") == "previous good output"
    assert sorted(p.name for p in out.iterdir()) == ["s.enriched.sarif"]


def test_r9_second_target_symlink_writes_nothing(tmp_path: Path) -> None:
    source = _copy("rule_id.sarif", tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    (out / enrich.SUMMARY_JSON).symlink_to(victim)
    args = ["enrich", str(source), "--out", str(out), "--format", "sarif,json"]
    assert runner.invoke(app, args).exit_code == 2
    assert not (out / "rule_id.enriched.sarif").exists()
    assert victim.read_text(encoding="utf-8") == "keep"


def test_r10_not_enriched_breakdown() -> None:
    document = _doc(
        [
            {"ruleId": "MCP01", "properties": None},
            {"ruleId": "MCP01", "properties": "odd"},
            {"ruleId": "none"},
            {"ruleId": "MCP01"},
        ]
    )
    summary = enrich.enrich_document(document)
    assert (summary.enriched, summary.properties_not_object, summary.no_id) == (1, 2, 1)
    data = summary.to_dict()
    assert data["not_enriched"] == 3
    assert data["not_enriched_breakdown"] == {
        "no_mcp_id": 1,
        "id_without_crosswalk": 0,
        "properties_not_an_object": 2,
    }
    md = enrich.render_summary_markdown(summary)
    assert "result `properties` is not an object: 2" in md


def test_r11_preexisting_blocks_are_counted_and_flagged() -> None:
    forged = {"ruleId": "X", "properties": {enrich.PROPERTY_KEY: {"controls": ["fake"]}}}
    summary = enrich.enrich_document(_doc([forged]))
    assert summary.foreign_blocks == 1
    assert summary.to_dict()["preexisting_mcp_crosswalk_blocks_left_untouched"] == 1
    assert "was not written by this run of mcpxw" in enrich.render_summary_markdown(summary)
    # A result with a real ID gets its block replaced by mcpxw's own.
    replaced = {"ruleId": "MCP01", "properties": {enrich.PROPERTY_KEY: {"controls": ["fake"]}}}
    enrich.enrich_document(_doc([replaced]))
    assert replaced["properties"][enrich.PROPERTY_KEY]["controls"] != ["fake"]
