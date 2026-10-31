"""Derived federal context for SP 800-53 controls: baseline membership and 800-171r3 links.

Both are computed from vendored NIST OSCAL files at runtime and never stored in the crosswalk YAML.

- **Baselines.** A control is in the LOW, MODERATE, HIGH, or PRIVACY baseline when its OSCAL ID
  (``ac-2``, ``ac-2.1``) appears in that baseline's resolved-profile catalog. Exact ID match.
- **SP 800-171 Rev 3 (derived).** Each 800-171r3 requirement links (``rel: reference``) to
  back-matter resources whose titles name its source 800-53 controls in zero-padded form
  (``IA-05(01)``). Inverting those links gives, for an 800-53 control, the requirements that cite
  it. Exact ID match only: a mapping to ``IA-5`` does not inherit requirements that cite only
  ``IA-5(1)``. Withdrawn requirements and references that are not 800-53 IDs are ignored. These
  links are derived, not authored mappings, and never count toward mapping totals.
"""

from __future__ import annotations

import json
import re
from functools import cache
from typing import Any, Literal

from mcp_crosswalk import resources
from mcp_crosswalk.catalogs import normalize_id

BaselineName = Literal["LOW", "MODERATE", "HIGH", "PRIVACY"]
BASELINES: tuple[BaselineName, ...] = ("LOW", "MODERATE", "HIGH", "PRIVACY")
BASELINE_FILES: dict[BaselineName, str] = {
    name: "nist-800-53r5-baselines/"
    f"NIST_SP-800-53_rev5_{name}-baseline-resolved-profile_catalog.json"
    for name in BASELINES
}
SP800_171R3_FILE = "nist-800-171r3/NIST_SP800-171_rev3_catalog.json"

SP800_171R3_LABEL = "800-171r3 (derived via source 800-53 control)"
CMMC_NOTE = (
    "CMMC Level 2 assessments reference SP 800-171 Rev 2, not Rev 3, so these derived Rev 3 links "
    "do not indicate CMMC alignment."
)

_REQUIREMENT_ID = re.compile(r"^SP_800_171_(\d{2}\.\d{2}\.\d{2})$")
# Source-control resource titles: two letters, a zero-padded number, optional enhancement.
_SOURCE_CONTROL_TITLE = re.compile(r"^[A-Z]{2}-\d+(?:\(\d+\))?$")


def _is_withdrawn(node: dict[str, Any]) -> bool:
    return any(
        p.get("name") == "status" and str(p.get("value", "")).lower() == "withdrawn"
        for p in node.get("props", []) or []
    )


def _walk(controls: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for control in controls or []:
        found.append(control)
        found.extend(_walk(control.get("controls")))
    return found


def _all_controls(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    controls = _walk(catalog.get("controls"))
    for group in catalog.get("groups", []) or []:
        controls.extend(_walk(group.get("controls")))
    return controls


def parse_baseline(raw: bytes) -> frozenset[str]:
    """OSCAL IDs of the (non-withdrawn) controls in a resolved baseline catalog."""
    catalog = json.loads(raw)["catalog"]
    return frozenset(str(c["id"]) for c in _all_controls(catalog) if not _is_withdrawn(c))


def parse_sp800_171r3(raw: bytes) -> dict[str, tuple[str, ...]]:
    """Reverse index: 800-53 OSCAL ID -> sorted 800-171r3 requirement numbers that cite it."""
    catalog = json.loads(raw)["catalog"]
    titles = {
        str(r.get("uuid")): str(r.get("title", ""))
        for r in catalog.get("back-matter", {}).get("resources", []) or []
    }
    index: dict[str, set[str]] = {}
    for requirement in _all_controls(catalog):
        match = _REQUIREMENT_ID.match(str(requirement.get("id", "")))
        if match is None or _is_withdrawn(requirement):
            continue
        for link in requirement.get("links", []) or []:
            if link.get("rel") != "reference":
                continue
            title = titles.get(str(link.get("href", "")).removeprefix("#"), "")
            if not _SOURCE_CONTROL_TITLE.match(title):
                continue  # e.g. "SP 800-63-3": not a source 800-53 control
            key = normalize_id("nist-800-53r5", title)
            if key is not None:
                index.setdefault(key, set()).add(match.group(1))
    return {key: tuple(sorted(numbers)) for key, numbers in sorted(index.items())}


@cache
def baseline_members(name: BaselineName) -> frozenset[str]:
    return parse_baseline((resources.frameworks_dir() / BASELINE_FILES[name]).read_bytes())


@cache
def sp800_171r3_index() -> dict[str, tuple[str, ...]]:
    return parse_sp800_171r3((resources.frameworks_dir() / SP800_171R3_FILE).read_bytes())


def baselines_for(framework: str, control_id: str) -> list[str]:
    """Baselines (in LOW, MODERATE, HIGH, PRIVACY order) that include an 800-53 control."""
    if framework != "nist-800-53r5":
        return []
    key = normalize_id(framework, control_id)
    if key is None:
        return []
    return [name for name in BASELINES if key in baseline_members(name)]


def sp800_171r3_for(framework: str, control_id: str) -> list[str]:
    """800-171r3 requirement numbers (``03.05.07``) that cite exactly this 800-53 control."""
    if framework != "nist-800-53r5":
        return []
    key = normalize_id(framework, control_id)
    if key is None:
        return []
    return list(sp800_171r3_index().get(key, ()))
