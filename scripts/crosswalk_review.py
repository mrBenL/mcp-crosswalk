"""Crosswalk review worksheet: export the mappings to CSV, then apply the owner's decisions.

Usage (from the repo root):

    uv run python scripts/crosswalk_review.py export [--out docs/review/crosswalk-review.csv]
    uv run python scripts/crosswalk_review.py apply [--worksheet PATH] [--write]

``export`` writes one row per mapping with the control's own text from the vendored NIST catalog and
blank ``decision``, ``new_relationship``, and ``notes`` columns.

``apply`` reads a completed worksheet. ``keep`` changes nothing, ``change`` sets the relationship to
``new_relationship``, and ``drop`` removes the mapping. A crosswalk file is set to
``review_status: reviewed`` only when every one of its mappings has a decision. Without ``--write``
it only prints the plan. With ``--write`` it first validates the result in a temporary copy, and
writes nothing if validation fails. Edits are made line by line, so comments and formatting are
kept.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import get_args

from mcp_crosswalk import catalogs
from mcp_crosswalk import crosswalk as cw
from mcp_crosswalk.csvsafe import safe_row
from mcp_crosswalk.models import Relationship
from mcp_crosswalk.resources import crosswalk_dir

DEFAULT_WORKSHEET = Path("docs/review/crosswalk-review.csv")
COLUMNS = (
    "risk_id",
    "risk_title",
    "framework",
    "control_id",
    "control_title",
    "relationship",
    "confidence",
    "rationale",
    "check_ids",
    "control_text",
    "decision",
    "new_relationship",
    "notes",
)
DECISIONS = ("keep", "change", "drop")
RELATIONSHIPS: tuple[str, ...] = get_args(Relationship)
BLOCK_START = re.compile(r"^  - framework: (\S+)\s*$")
CONTROL_LINE = re.compile(r"^    control_id: (\S+)\s*$")
RELATIONSHIP_LINE = re.compile(r"^(    relationship: )(\S+)(\s*)$")
DRAFT_STATUS = "review_status: draft\n"
DRAFT_HEADER = "Draft, pending practitioner review."
REVIEWED_HEADER = "Reviewed by the maintainer."

Key = tuple[str, str, str]  # risk_id, framework, control_id


class ReviewError(ValueError):
    """The worksheet cannot be applied."""


def export_rows(directory: Path | None = None) -> list[dict[str, str]]:
    owasp = {risk.short_id: risk.title for risk in cw.load_owasp_catalog().risks}
    rows = []
    for risk_id, cw_file in sorted(cw.load_crosswalk(directory).items()):
        for mapping in cw_file.mappings:
            entry = catalogs.lookup(mapping.framework, mapping.control_id)
            rows.append(
                {
                    "risk_id": risk_id,
                    "risk_title": owasp.get(risk_id, ""),
                    "framework": mapping.framework,
                    "control_id": mapping.control_id,
                    "control_title": entry.title if entry else "",
                    "relationship": mapping.relationship,
                    "confidence": mapping.confidence,
                    "rationale": " ".join(mapping.rationale.split()),
                    "check_ids": " ".join(mapping.check_ids),
                    "control_text": entry.statement if entry else "",
                    "decision": "",
                    "new_relationship": "",
                    "notes": "",
                }
            )
    return rows


def write_worksheet(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(safe_row(dict(row)) for row in rows)


@dataclass
class Plan:
    """What applying a worksheet would do."""

    changes: dict[Key, str] = field(default_factory=dict)  # key -> new relationship
    drops: set[Key] = field(default_factory=set)
    kept: set[Key] = field(default_factory=set)
    reviewed_files: list[str] = field(default_factory=list)
    undecided: dict[str, int] = field(default_factory=dict)  # risk_id -> rows without a decision


def _cell(row: dict[str, str | None], column: str) -> str:
    return (row.get(column) or "").strip()


def read_decisions(path: Path) -> dict[Key, tuple[str, str]]:
    """Worksheet rows that carry a decision: key -> (decision, new_relationship)."""
    # utf-8-sig: spreadsheets often add a byte-order mark when saving CSV.
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = {"risk_id", "framework", "control_id", "decision", "new_relationship"} - set(
            reader.fieldnames or []
        )
        if missing:
            raise ReviewError(f"worksheet is missing column(s): {', '.join(sorted(missing))}")
        decisions: dict[Key, tuple[str, str]] = {}
        seen: set[Key] = set()
        for line, row in enumerate(reader, start=2):
            key = (_cell(row, "risk_id"), _cell(row, "framework"), _cell(row, "control_id"))
            if key in seen:
                raise ReviewError(f"line {line}: duplicate row for {' '.join(key)}")
            seen.add(key)
            decision = _cell(row, "decision").lower()
            new_relationship = _cell(row, "new_relationship").lower()
            if not decision:
                if new_relationship:
                    raise ReviewError(f"line {line}: new_relationship given without a decision")
                continue
            if decision not in DECISIONS:
                raise ReviewError(
                    f"line {line}: decision {decision!r} is not one of {', '.join(DECISIONS)}"
                )
            if decision == "change" and new_relationship not in RELATIONSHIPS:
                raise ReviewError(
                    f"line {line}: change needs new_relationship, one of {', '.join(RELATIONSHIPS)}"
                    " (edit the YAML by hand for other changes)"
                )
            if decision != "change" and new_relationship:
                raise ReviewError(f"line {line}: new_relationship is only used with change")
            decisions[key] = (decision, new_relationship)
    return decisions


def build_plan(decisions: dict[Key, tuple[str, str]], directory: Path) -> Plan:
    crosswalk = cw.load_crosswalk(directory)
    current: dict[Key, str] = {
        (risk_id, m.framework, m.control_id): m.relationship
        for risk_id, cw_file in crosswalk.items()
        for m in cw_file.mappings
    }
    unknown = sorted(set(decisions) - set(current))
    if unknown:
        raise ReviewError(
            f"worksheet rows not in the crosswalk: {', '.join(map(' '.join, unknown))}"
        )
    plan = Plan()
    for key, (decision, new_relationship) in decisions.items():
        if decision == "drop":
            plan.drops.add(key)
        elif decision == "change" and new_relationship != current[key]:
            plan.changes[key] = new_relationship
        else:
            plan.kept.add(key)
    for risk_id, cw_file in sorted(crosswalk.items()):
        keys = [(risk_id, m.framework, m.control_id) for m in cw_file.mappings]
        undecided = sum(1 for key in keys if key not in decisions)
        if undecided:
            plan.undecided[risk_id] = undecided
        elif cw_file.review_status == "draft":
            plan.reviewed_files.append(risk_id)
    return plan


def apply_to_text(text: str, risk_id: str, plan: Plan) -> str:
    """Apply the plan to one crosswalk file's text, line by line."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    index = 0
    while index < len(lines):
        start = BLOCK_START.match(lines[index])
        if not start:
            out.append(lines[index])
            index += 1
            continue
        end = index + 1
        while end < len(lines) and not BLOCK_START.match(lines[end]) and lines[end].startswith(" "):
            end += 1
        block = lines[index:end]
        control = CONTROL_LINE.match(block[1]) if len(block) > 1 else None
        if control is None:
            raise ReviewError(f"{risk_id}: mapping block without control_id on its second line")
        key = (risk_id, start.group(1), control.group(1))
        if key not in plan.drops:
            if key in plan.changes:
                block = [
                    RELATIONSHIP_LINE.sub(rf"\g<1>{plan.changes[key]}\g<3>", line) for line in block
                ]
            out.extend(block)
        index = end
    result = "".join(out)
    if risk_id in plan.reviewed_files:
        if DRAFT_STATUS not in result:
            raise ReviewError(f"{risk_id}: no 'review_status: draft' line found")
        result = result.replace(DRAFT_STATUS, "review_status: reviewed\n", 1)
        result = result.replace(DRAFT_HEADER, REVIEWED_HEADER, 1)
    return result


def apply_plan(plan: Plan, directory: Path, write: bool) -> list[str]:
    """Validate the result in a temporary copy; write it only when valid and ``write`` is set."""
    risks = sorted({key[0] for key in (*plan.changes, *plan.drops)} | set(plan.reviewed_files))
    updated = {
        risk_id: apply_to_text(
            (directory / f"{risk_id}.yaml").read_text(encoding="utf-8"), risk_id, plan
        )
        for risk_id in risks
    }
    with tempfile.TemporaryDirectory() as tmp:
        for source in directory.glob("*.yaml"):
            target = Path(tmp) / source.name
            target.write_text(
                updated.get(source.stem, source.read_text(encoding="utf-8")), encoding="utf-8"
            )
        problems = cw.validate_crosswalk(Path(tmp))
    if problems:
        return problems
    if write:
        for risk_id, text in updated.items():
            (directory / f"{risk_id}.yaml").write_text(text, encoding="utf-8")
    return []


def _print_plan(plan: Plan) -> None:
    print(f"keep: {len(plan.kept)}  change: {len(plan.changes)}  drop: {len(plan.drops)}")
    for key, value in sorted(plan.changes.items()):
        print(f"  change {' '.join(key)} -> {value}")
    for key in sorted(plan.drops):
        print(f"  drop   {' '.join(key)}")
    print(f"files to mark reviewed: {', '.join(plan.reviewed_files) or '(none)'}")
    for risk_id, count in sorted(plan.undecided.items()):
        print(f"  {risk_id} stays as it is: {count} mapping(s) without a decision")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export", help="Write the review worksheet.")
    export.add_argument("--out", type=Path, default=DEFAULT_WORKSHEET)
    export.add_argument("--crosswalk-dir", type=Path, default=None)
    apply = sub.add_parser("apply", help="Apply a completed worksheet to the crosswalk YAML.")
    apply.add_argument("--worksheet", type=Path, default=DEFAULT_WORKSHEET)
    apply.add_argument("--crosswalk-dir", type=Path, default=None)
    apply.add_argument("--write", action="store_true", help="Change the files (default: preview).")
    args = parser.parse_args(argv)

    directory: Path = args.crosswalk_dir or crosswalk_dir()
    if args.command == "export":
        rows = export_rows(directory)
        write_worksheet(args.out, rows)
        print(f"Wrote {len(rows)} mappings to {args.out}")
        return 0

    try:
        plan = build_plan(read_decisions(args.worksheet), directory)
        _print_plan(plan)
        problems = apply_plan(plan, directory, args.write)
    except (ReviewError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if problems:
        print("The result would not validate; nothing was written:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    if args.write:
        print(
            "Applied. Next: run uv run mcpxw crosswalk validate, then regenerate "
            "docs/crosswalk.md and docs/crosswalk.csv with crosswalk export."
        )
    else:
        print("Preview only. Re-run with --write to change the files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
