"""Load the vendored NIST OSCAL catalogs and resolve control / subcategory IDs.

SP 800-53 Rev 5 IDs are lowercase in OSCAL (``ac-2``, enhancement ``ac-2.1``) and are displayed as
``AC-2`` / ``AC-2(1)``. Either form is accepted as input. CSF 2.0 subcategories (``GV.OC-01``) are
the only valid CSF targets; their readable text comes from the ``statement`` part.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Literal

from mcp_crosswalk.resources import frameworks_dir

FrameworkId = Literal["nist-800-53r5", "nist-csf-2.0"]
FRAMEWORKS: tuple[FrameworkId, ...] = ("nist-800-53r5", "nist-csf-2.0")

CATALOG_FILES: dict[FrameworkId, str] = {
    "nist-800-53r5": "nist-800-53r5/NIST_SP-800-53_rev5_catalog.json",
    "nist-csf-2.0": "nist-csf-2.0/NIST_CSF_v2.0_catalog.json",
}

FRAMEWORK_NAMES: dict[FrameworkId, str] = {
    "nist-800-53r5": "NIST SP 800-53 Rev 5",
    "nist-csf-2.0": "NIST CSF 2.0",
}

_SP800_53_DISPLAY = re.compile(r"^\s*([A-Za-z]{2})-0*(\d+)(?:\s*\(\s*0*(\d+)\s*\))?\s*$")
_SP800_53_OSCAL = re.compile(r"^\s*([A-Za-z]{2})-0*(\d+)(?:\.0*(\d+))?\s*$")
_CSF_SUBCATEGORY = re.compile(r"^\s*([A-Za-z]{2})\.([A-Za-z]{2})-(\d{2})\s*$")
_PARAM_INSERT = re.compile(r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}")


@dataclass(frozen=True)
class CatalogEntry:
    """One resolvable control (800-53) or subcategory (CSF 2.0)."""

    framework: FrameworkId
    id: str  # display form, e.g. "AC-2(1)" or "PR.AA-01"
    oscal_id: str  # catalog form, e.g. "ac-2.1" or "PR.AA-01"
    title: str
    statement: str
    withdrawn: bool


@dataclass(frozen=True)
class Catalog:
    framework: FrameworkId
    title: str
    version: str
    source_sha256: str
    entries: dict[str, CatalogEntry]  # keyed by oscal_id

    def lookup(self, control_id: str) -> CatalogEntry | None:
        key = normalize_id(self.framework, control_id)
        if key is None:
            return None
        return self.entries.get(key)


def normalize_id(framework: str, control_id: str) -> str | None:
    """Return the OSCAL key for an ID in either display or OSCAL form, or None if malformed."""
    if framework == "nist-800-53r5":
        match = _SP800_53_DISPLAY.match(control_id) or _SP800_53_OSCAL.match(control_id)
        if match is None:
            return None
        family, number, enhancement = match.groups()
        base = f"{family.lower()}-{int(number)}"
        return f"{base}.{int(enhancement)}" if enhancement else base
    if framework == "nist-csf-2.0":
        match = _CSF_SUBCATEGORY.match(control_id)
        if match is None:
            return None
        function, category, number = match.groups()
        return f"{function.upper()}.{category.upper()}-{number}"
    return None


def display_id(framework: str, oscal_id: str) -> str:
    """Convert an OSCAL key to its display form (``ac-2.1`` -> ``AC-2(1)``)."""
    if framework == "nist-800-53r5":
        base, _, enhancement = oscal_id.partition(".")
        family, _, number = base.partition("-")
        shown = f"{family.upper()}-{int(number)}"
        return f"{shown}({int(enhancement)})" if enhancement else shown
    return oscal_id


def _props(node: dict[str, Any]) -> list[dict[str, Any]]:
    props = node.get("props", [])
    return props if isinstance(props, list) else []


def _is_withdrawn(node: dict[str, Any]) -> bool:
    return any(
        p.get("name") == "status" and str(p.get("value", "")).lower() == "withdrawn"
        for p in _props(node)
    )


def _param_text(params: dict[str, dict[str, Any]], param_id: str) -> str:
    param = params.get(param_id, {})
    if "label" in param:
        return f"[Assignment: {param['label']}]"
    select = param.get("select")
    if isinstance(select, dict):
        choices = select.get("choice", [])
        how = "one or more" if select.get("how-many") == "one-or-more" else "one"
        return f"[Selection ({how}): {'; '.join(str(c) for c in choices)}]"
    return "[Assignment: organization-defined value]"


def _render_prose(text: str, params: dict[str, dict[str, Any]]) -> str:
    # Parameters can nest (a selection whose choices insert other params), so resolve repeatedly.
    for _ in range(5):
        rendered = _PARAM_INSERT.sub(lambda m: _param_text(params, m.group(1)), text)
        if rendered == text:
            break
        text = rendered
    return text


def _label(node: dict[str, Any]) -> str:
    for p in _props(node):
        if p.get("name") == "label" and "class" not in p:
            return str(p.get("value", ""))
    return ""


def _flatten_statement(part: dict[str, Any], params: dict[str, dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    prose = str(part.get("prose", "")).strip()
    label = _label(part)
    if prose:
        lines.append(f"{label} {_render_prose(prose, params)}".strip())
    for child in part.get("parts", []) or []:
        lines.extend(_flatten_statement(child, params))
    return lines


def _statement(node: dict[str, Any], params: dict[str, dict[str, Any]]) -> str:
    for part in node.get("parts", []) or []:
        if part.get("name") == "statement":
            return " ".join(_flatten_statement(part, params))
    return ""


def _collect_params(node: dict[str, Any], inherited: dict[str, dict[str, Any]]) -> dict[str, Any]:
    params = dict(inherited)
    for param in node.get("params", []) or []:
        if isinstance(param, dict) and "id" in param:
            params[str(param["id"])] = param
    return params


def _walk_800_53(
    controls: list[dict[str, Any]],
    entries: dict[str, CatalogEntry],
    parent_title: str | None,
    params: dict[str, dict[str, Any]],
) -> None:
    for control in controls:
        oscal_id = str(control["id"])
        local_params = _collect_params(control, params)
        title = str(control.get("title", ""))
        full_title = f"{parent_title} | {title}" if parent_title else title
        entries[oscal_id] = CatalogEntry(
            framework="nist-800-53r5",
            id=display_id("nist-800-53r5", oscal_id),
            oscal_id=oscal_id,
            title=full_title,
            statement=_statement(control, local_params),
            withdrawn=_is_withdrawn(control),
        )
        _walk_800_53(control.get("controls", []) or [], entries, title, local_params)


def _walk_csf(nodes: list[dict[str, Any]], entries: dict[str, CatalogEntry]) -> None:
    for node in nodes:
        if node.get("class") == "subcategory":
            oscal_id = str(node["id"])
            statement = _statement(node, {})
            entries[oscal_id] = CatalogEntry(
                framework="nist-csf-2.0",
                id=oscal_id,
                oscal_id=oscal_id,
                title=statement or str(node.get("title", oscal_id)),
                statement=statement,
                withdrawn=_is_withdrawn(node),
            )
        _walk_csf(node.get("controls", []) or [], entries)
        _walk_csf(node.get("groups", []) or [], entries)


def parse_catalog(framework: FrameworkId, raw: bytes) -> Catalog:
    """Parse OSCAL catalog bytes into a Catalog index."""
    document = json.loads(raw)
    catalog = document["catalog"]
    metadata = catalog.get("metadata", {})
    entries: dict[str, CatalogEntry] = {}
    groups: list[dict[str, Any]] = catalog.get("groups", []) or []
    if framework == "nist-800-53r5":
        for group in groups:
            _walk_800_53(group.get("controls", []) or [], entries, None, {})
        _walk_800_53(catalog.get("controls", []) or [], entries, None, {})
    else:
        _walk_csf(groups, entries)
        _walk_csf(catalog.get("controls", []) or [], entries)
    return Catalog(
        framework=framework,
        title=str(metadata.get("title", "")),
        version=str(metadata.get("version", "")),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        entries=entries,
    )


def load_catalog_file(framework: FrameworkId, path: Path) -> Catalog:
    return parse_catalog(framework, path.read_bytes())


@cache
def load_catalog(framework: FrameworkId) -> Catalog:
    """Load (and cache) the vendored catalog for a framework."""
    if framework not in CATALOG_FILES:
        raise KeyError(f"unknown framework: {framework}")
    return load_catalog_file(framework, frameworks_dir() / CATALOG_FILES[framework])


def lookup(framework: str, control_id: str) -> CatalogEntry | None:
    """Resolve an ID in a framework. Returns None for unknown frameworks or IDs.

    Withdrawn 800-53 controls are returned with ``withdrawn=True`` so callers can report them.
    """
    if framework not in CATALOG_FILES:
        return None
    fw: FrameworkId = "nist-800-53r5" if framework == "nist-800-53r5" else "nist-csf-2.0"
    return load_catalog(fw).lookup(control_id)
