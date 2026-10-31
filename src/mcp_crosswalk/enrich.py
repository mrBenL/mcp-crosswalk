"""``mcpxw enrich``: add crosswalk controls to another tool's SARIF results.

The input is untrusted. It is size-capped, parsed as strict JSON, and only read: no URI in it is
ever resolved or fetched, and nothing in it is executed. For each result that names an OWASP MCP
Top 10 risk ID, ``properties["mcp-crosswalk"]`` and ``nist-...`` tags are added; every other field
is left exactly as parsed.

Risk IDs are matched as ``MCP01`` to ``MCP10`` (optionally ``:20NN``), case-insensitively, as
whole tokens, and are assumed to use the official OWASP numbering of the selected catalog version.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_crosswalk import versions
from mcp_crosswalk.crosswalk import load_version_crosswalk
from mcp_crosswalk.engine import control_ref
from mcp_crosswalk.models import DISCLAIMER, CrosswalkFile
from mcp_crosswalk.safewrite import UnsafeOutputError, write_files

MAX_SARIF_BYTES = 50 * 1024 * 1024
PROPERTY_KEY = "mcp-crosswalk"
# The spec's pattern \bMCP(0[1-9]|10)(?::20\d\d)?\b, with the end anchored so it cannot backtrack
# out of a malformed suffix: "MCP07:2025x" and "MCP07:1999" are not read as MCP07.
MCP_ID = re.compile(r"\bMCP(0[1-9]|10)(?::20\d\d)?(?!\w)(?!:\d)", re.IGNORECASE)
# Free-text messages also name hosts, paths, and package names ("mcp05.internal.example.com",
# "servers/mcp01/config.json", "mcp-server-mcp03"). In message text an ID must not be glued to a
# preceding or following '.', '/', or '-' word.
MESSAGE_MCP_ID = re.compile(
    r"(?<![\w./\-])MCP(0[1-9]|10)(?::20\d\d)?(?!\w)(?!:\d)(?![./\-]\w)", re.IGNORECASE
)
TAG_PREFIX = {"nist-800-53r5": "nist-800-53r5/", "nist-csf-2.0": "nist-csf-2.0/"}

ID_SCHEME_NOTE = (
    "enrich assumes the input uses the official OWASP MCP Top 10 numbering for the selected "
    "catalog version. Some tools use their own MCP numbering (for example, labeling prompt "
    "injection MCP01, while OWASP's MCP01 is Token Mismanagement & Secret Exposure). Confirm "
    "that your scanner uses the official IDs before relying on the added controls."
)


class EnrichInputError(ValueError):
    """The input file is not usable SARIF (too large, malformed, or not SARIF 2.1.0)."""


@dataclass
class EnrichSummary:
    input_name: str
    catalog_version: str
    runs: int = 0
    total_results: int = 0
    enriched: int = 0
    no_id: int = 0
    id_without_crosswalk: int = 0
    properties_not_object: int = 0
    foreign_blocks: int = 0
    per_risk: Counter[str] = field(default_factory=Counter)
    unmapped_ids: Counter[str] = field(default_factory=Counter)

    @property
    def not_enriched(self) -> int:
        return self.no_id + self.id_without_crosswalk + self.properties_not_object

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input_name,
            "catalog_version": self.catalog_version,
            "runs": self.runs,
            "total_results": self.total_results,
            "enriched": self.enriched,
            "not_enriched": self.not_enriched,
            "not_enriched_breakdown": {
                "no_mcp_id": self.no_id,
                "id_without_crosswalk": self.id_without_crosswalk,
                "properties_not_an_object": self.properties_not_object,
            },
            "preexisting_mcp_crosswalk_blocks_left_untouched": self.foreign_blocks,
            "per_risk": dict(sorted(self.per_risk.items())),
            "ids_without_crosswalk": dict(sorted(self.unmapped_ids.items())),
            "id_scheme_note": ID_SCHEME_NOTE,
            "disclaimer": DISCLAIMER,
        }


# --- Input --------------------------------------------------------------------------------------


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnrichInputError("input has a duplicate JSON object key; refusing to rewrite it")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise EnrichInputError(f"input contains the non-standard JSON constant {name}")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        # 1e400 parses as infinity, which json.dumps would write back as the non-JSON "Infinity".
        raise EnrichInputError("input contains a number too large to represent")
    return value


def load_sarif(path: Path) -> dict[str, Any]:
    """Read and structurally check a SARIF 2.1.0 log. Raises EnrichInputError on bad input."""
    try:
        if not path.is_file():
            raise EnrichInputError(f"input {path} is not a file")
        if path.stat().st_size > MAX_SARIF_BYTES:
            raise EnrichInputError(f"input is larger than {MAX_SARIF_BYTES} bytes")
        with path.open("rb") as handle:
            raw = handle.read(MAX_SARIF_BYTES + 1)
    except OSError as exc:
        raise EnrichInputError(f"cannot read input ({type(exc).__name__})") from exc
    if len(raw) > MAX_SARIF_BYTES:
        raise EnrichInputError(f"input is larger than {MAX_SARIF_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except EnrichInputError:
        raise
    except UnicodeDecodeError as exc:
        raise EnrichInputError("input is not UTF-8 text") from exc
    except json.JSONDecodeError as exc:
        raise EnrichInputError(
            f"input is not valid JSON (line {exc.lineno} column {exc.colno}: {exc.msg})"
        ) from exc
    except RecursionError as exc:
        raise EnrichInputError("input JSON nesting is too deep") from exc
    except ValueError as exc:
        raise EnrichInputError(f"input has an invalid JSON value ({type(exc).__name__})") from exc
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise EnrichInputError('input is not a SARIF 2.1.0 log (expected "version": "2.1.0")')
    runs = document.get("runs")
    if not isinstance(runs, list) or not all(isinstance(run, dict) for run in runs):
        raise EnrichInputError('input is not a SARIF 2.1.0 log ("runs" must be a list of objects)')
    for run in runs:
        results = run.get("results")
        if results is not None and (
            not isinstance(results, list) or not all(isinstance(r, dict) for r in results)
        ):
            raise EnrichInputError('input is not a SARIF 2.1.0 log ("results" must be objects)')
    return document


# --- ID extraction ------------------------------------------------------------------------------


def find_ids(text: object, pattern: re.Pattern[str] = MCP_ID) -> set[str]:
    """Normalized OWASP MCP risk IDs (``MCP01`` to ``MCP10``) in a string; empty for non-strings."""
    if not isinstance(text, str):
        return set()
    return {f"MCP{match.group(1)}" for match in pattern.finditer(text)}


def find_message_ids(text: object) -> set[str]:
    """Like ``find_ids``, but stricter for free text, where hosts and paths can look like IDs."""
    return find_ids(text, MESSAGE_MCP_ID)


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _rule_texts(rule: object) -> Iterator[object]:
    rule = _dict(rule)
    yield rule.get("id")
    yield rule.get("name")
    yield _dict(rule.get("shortDescription")).get("text")
    yield from _list(_dict(rule.get("properties")).get("tags"))


class RuleIndex:
    """Rules of one run, grouped by tool component, with an ID index built once per component.

    Component ``None`` is the driver; an integer is ``tool.extensions[i]``.
    """

    def __init__(self, run: dict[str, Any]) -> None:
        tool = _dict(run.get("tool"))
        self._rules: dict[int | None, list[Any]] = {
            None: _list(_dict(tool.get("driver")).get("rules"))
        }
        for i, extension in enumerate(_list(tool.get("extensions"))):
            self._rules[i] = _list(_dict(extension).get("rules"))
        self._by_id: dict[int | None, dict[str, list[Any]]] = {}

    def rules(self, component: int | None) -> list[Any]:
        return self._rules.get(component, [])

    def by_id(self, component: int | None, rule_id: str) -> list[Any]:
        if component not in self._by_id:
            index: dict[str, list[Any]] = {}
            for rule in self.rules(component):
                if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                    index.setdefault(rule["id"], []).append(rule)
            self._by_id[component] = index
        return self._by_id[component].get(rule_id, [])


def matching_rules(run: dict[str, Any] | RuleIndex, result: dict[str, Any]) -> list[Any]:
    """The rules a result refers to, looked up only in the tool component that owns the result.

    SARIF 2.1.0: ``ruleIndex``/``rule.index`` and rule IDs are relative to the component named by
    ``rule.toolComponent.index`` (an extension), or to the driver when none is named.
    """
    index = run if isinstance(run, RuleIndex) else RuleIndex(run)
    reference = _dict(result.get("rule"))
    component = _int(_dict(reference.get("toolComponent")).get("index"))
    rules = index.rules(component)
    found: list[Any] = []
    for position in {_int(reference.get("index")), _int(result.get("ruleIndex"))}:
        if position is not None and 0 <= position < len(rules):
            found.append(rules[position])
    for rule_id in {result.get("ruleId"), reference.get("id")}:
        if isinstance(rule_id, str):
            found += [r for r in index.by_id(component, rule_id) if r not in found]
    return found


def result_risk_ids(run: dict[str, Any] | RuleIndex, result: dict[str, Any]) -> set[str]:
    """Every OWASP MCP risk ID that a result names, from all the places the spec lists."""
    texts: list[object] = [result.get("ruleId")]
    texts += _list(_dict(result.get("properties")).get("tags"))
    for rule in matching_rules(run, result):
        texts += list(_rule_texts(rule))
    ids = find_message_ids(_dict(result.get("message")).get("text"))
    for text in texts:
        ids |= find_ids(text)
    return ids


# --- Enrichment ---------------------------------------------------------------------------------


def _controls(risk_ids: list[str], crosswalk: dict[str, CrosswalkFile]) -> list[dict[str, Any]]:
    controls = []
    for risk_id in risk_ids:
        for mapping in crosswalk[risk_id].mappings:
            ref = control_ref(risk_id, mapping)
            controls.append(
                {
                    "risk_id": ref.risk_id,
                    "framework": ref.framework,
                    "control_id": ref.control_id,
                    "title": ref.title,
                    "relationship": ref.relationship,
                    "confidence": ref.confidence,
                    "baselines": ref.baselines,
                }
            )
    return controls


def enrich_document(
    document: dict[str, Any], catalog_version: str | None = None, input_name: str = ""
) -> EnrichSummary:
    """Enrich a parsed SARIF log in place and return the summary."""
    version = versions.resolve(catalog_version).id
    crosswalk = load_version_crosswalk(version)
    summary = EnrichSummary(input_name=input_name, catalog_version=version)
    controls_cache: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for run in document["runs"]:
        summary.runs += 1
        rule_index = RuleIndex(run)
        for result in run.get("results") or []:
            summary.total_results += 1
            found = result_risk_ids(rule_index, result)
            known = sorted(r for r in found if r in crosswalk)
            for risk_id in found - set(known):
                summary.unmapped_ids[risk_id] += 1
            properties = result.get("properties", {})
            if not known:
                if found:
                    summary.id_without_crosswalk += 1
                else:
                    summary.no_id += 1
                if isinstance(properties, dict) and PROPERTY_KEY in properties:
                    summary.foreign_blocks += 1
                continue
            if not isinstance(properties, dict):
                summary.properties_not_object += 1
                continue
            key = tuple(known)
            if key not in controls_cache:
                controls_cache[key] = _controls(known, crosswalk)
            controls = controls_cache[key]
            properties[PROPERTY_KEY] = {
                "catalog_version": version,
                "risk_ids": known,
                "controls": controls,
                "disclaimer": DISCLAIMER,
            }
            tags = properties.get("tags")
            if tags is None:
                tags = properties["tags"] = []
            if isinstance(tags, list):
                for control in controls:
                    tag = TAG_PREFIX[control["framework"]] + control["control_id"]
                    if tag not in tags:
                        tags.append(tag)
            result["properties"] = properties
            summary.enriched += 1
            summary.per_risk.update(known)
    return summary


ENRICH_FORMATS = ("sarif", "json", "md")
SUMMARY_JSON = "mcpxw-enrich-summary.json"
SUMMARY_MD = "mcpxw-enrich-summary.md"


def parse_enrich_formats(value: str) -> list[str]:
    requested = {part.strip().lower() for part in value.split(",") if part.strip()}
    unknown = requested - set(ENRICH_FORMATS)
    if unknown or not requested:
        raise ValueError(
            f"unknown format(s): {', '.join(sorted(unknown)) or '(none)'}; "
            f"choose from {', '.join(ENRICH_FORMATS)}"
        )
    return [name for name in ENRICH_FORMATS if name in requested]


def output_name(input_path: Path) -> str:
    """``<input stem>.enriched.sarif``; only the file's own name is used, never its directory."""
    return f"{input_path.stem}.enriched.sarif"


def write_outputs(out_dir: Path, files: dict[str, str], input_path: Path) -> list[Path]:
    """Write fixed-name files inside ``out_dir``: all targets are checked before any is written,
    symlinks are refused, and the input file is never overwritten."""
    try:
        return write_files(out_dir, files, protected=(input_path,))
    except UnsafeOutputError as exc:
        raise EnrichInputError(str(exc)) from exc


def render_sarif(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def render_summary_json(summary: EnrichSummary) -> str:
    return json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n"


def render_summary_markdown(summary: EnrichSummary) -> str:
    from mcp_crosswalk.reporters.markdown import esc

    lines = [
        "# mcpxw enrich summary",
        "",
        f"> {DISCLAIMER}",
        "",
        f"- Input: {esc(summary.input_name)}",
        f"- OWASP MCP Top 10 catalog version: {summary.catalog_version}",
        f"- Runs: {summary.runs}",
        f"- Results: {summary.total_results}",
        f"- Enriched (at least one OWASP MCP risk ID with a crosswalk): {summary.enriched}",
        f"- Not enriched: {summary.not_enriched}",
        f"  - no OWASP MCP risk ID: {summary.no_id}",
        f"  - risk ID with no crosswalk in this catalog version: {summary.id_without_crosswalk}",
        f"  - result `properties` is not an object: {summary.properties_not_object}",
        "",
        "| Risk | Results |",
        "|---|---|",
        *[f"| {risk} | {count} |" for risk, count in sorted(summary.per_risk.items())],
        "",
    ]
    if summary.unmapped_ids:
        ids = ", ".join(f"{r} ({n})" for r, n in sorted(summary.unmapped_ids.items()))
        lines += [f"IDs with no crosswalk in this catalog version (not enriched): {ids}", ""]
    if summary.foreign_blocks:
        lines += [
            f"{summary.foreign_blocks} result(s) without an OWASP MCP risk ID already carried a "
            f'`properties["{PROPERTY_KEY}"]` block in the input. It was left as-is and was not '
            "written by this run of mcpxw.",
            "",
        ]
    lines += [f"**ID numbering.** {ID_SCHEME_NOTE}", ""]
    return "\n".join(lines)
