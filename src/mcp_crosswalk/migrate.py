"""``mcpxw crosswalk migrate``: copy the crosswalk into a new OWASP catalog version's risk IDs.

The source crosswalk is never modified: migrated copies are written to a separate directory, which
may not be (or be inside) the source directory, any version's configured crosswalk directory, or
the ``catalog/`` directory. Retired risks are reported, not silently dropped, and risks that are new
in the target version (no source mapped onto them) are reported as gaps to author by hand.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mcp_crosswalk import resources, versions
from mcp_crosswalk.crosswalk import load_crosswalk
from mcp_crosswalk.models import CrosswalkFile


class MigrationOutputError(versions.VersionError):
    """The migration output directory is unsafe or the migration cannot run."""


@dataclass
class MigrationResult:
    from_version: str
    to_version: str
    renamed: list[tuple[str, str]] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    retired: list[tuple[str, int, str]] = field(default_factory=list)  # (risk, mappings, note)
    new_unmapped: list[str] = field(default_factory=list)
    written: list[Path] = field(default_factory=list)


def _same_or_inside(path: Path, directory: Path) -> bool:
    """True when ``path`` is ``directory`` or lies inside it.

    Compares resolved paths and, for every existing ancestor of ``path``, file identity
    (``os.path.samefile``), so letter case on case-insensitive file systems, ``..``, and symlinked
    parents cannot slip past the check.
    """
    resolved, target = path.resolve(), directory.resolve()
    if resolved == target or target in resolved.parents:
        return True
    if not target.exists():
        return False
    for candidate in (resolved, *resolved.parents):
        if candidate.exists() and os.path.samefile(candidate, target):
            return True
    return False


def _protected_dirs(source: Path) -> list[Path]:
    """The source crosswalk, every version's configured crosswalk, and the catalog directory."""
    protected = [source, resources.data_root() / "catalog"]
    for info in versions.load_versions().versions:
        if info.crosswalk:
            protected.append(resources.data_root() / info.crosswalk)
    return protected


def _check_output(out_dir: Path, forbidden: list[Path]) -> Path:
    if out_dir.is_symlink():
        raise MigrationOutputError(f"refusing to write through symlink {out_dir}")
    if out_dir.exists() and not out_dir.is_dir():
        raise MigrationOutputError(f"output path {out_dir} exists and is not a directory")
    resolved = out_dir.resolve()
    for directory in forbidden:
        if _same_or_inside(out_dir, directory):
            raise MigrationOutputError(
                f"refusing to write into {directory}: migration never writes in place; "
                "choose a separate --out directory"
            )
    return resolved


def _render(cw_file: CrosswalkFile, old_id: str, from_version: str, note: str) -> str:
    header = [
        f"# Migrated by `mcpxw crosswalk migrate` from {from_version} {old_id} "
        f"to {cw_file.catalog_version} {cw_file.risk_id}.",
        f"# Migration note: {' '.join(note.split())}",
        "# Review every mapping against the new risk definition before adopting this file.",
    ]
    body = yaml.safe_dump(
        cw_file.model_dump(mode="json"), sort_keys=False, allow_unicode=True, width=100
    )
    return "\n".join(header) + "\n" + body


def migrate_crosswalk(
    to_version: str, out_dir: Path, source_dir: Path | None = None
) -> MigrationResult:
    """Write migrated copies of the default version's crosswalk files into ``out_dir``."""
    target = versions.resolve(to_version)
    from_version = versions.default_version()
    if target.id == from_version:
        raise MigrationOutputError(f"{target.id} is already the default version; nothing to do")
    source = source_dir or versions.resolve(from_version).crosswalk_dir
    if source is None:
        raise MigrationOutputError(f"no crosswalk directory configured for {from_version}")
    migration = versions.load_migration(from_version, target.id)
    target_catalog = versions.load_owasp(target.id)
    crosswalk = load_crosswalk(source)

    resolved_out = _check_output(out_dir, _protected_dirs(source))

    result = MigrationResult(from_version=from_version, to_version=target.id)
    planned: dict[str, str] = {}
    for old_id, entry in sorted(migration.map.items()):
        cw_file = crosswalk.get(old_id)
        if entry.to is None:
            count = len(cw_file.mappings) if cw_file else 0
            result.retired.append((old_id, count, " ".join(entry.note.split())))
            continue
        if cw_file is None:
            continue  # no source file; the target risk shows up as new-and-unmapped below
        migrated = cw_file.model_copy(
            update={"risk_id": entry.to, "catalog_version": target.id, "review_status": "draft"}
        )
        planned[entry.to] = _render(migrated, old_id, from_version, entry.note)
        if entry.to == old_id:
            result.unchanged.append(old_id)
        else:
            result.renamed.append((old_id, entry.to))

    target_ids = (r.short_id for r in target_catalog.risks)
    result.new_unmapped = sorted(r for r in target_ids if r not in planned)

    resolved_out.mkdir(parents=True, exist_ok=True)
    for risk_id in sorted(planned):
        path = resolved_out / f"{risk_id}.yaml"
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise MigrationOutputError(f"refusing to overwrite {path}: not a regular file")
        path.write_text(planned[risk_id], encoding="utf-8", newline="\n")
        result.written.append(path)
    return result
