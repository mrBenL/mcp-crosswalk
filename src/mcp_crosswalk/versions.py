"""OWASP MCP Top 10 catalog versions and risk ID migrations between them.

``catalog/owasp-mcp/versions.yaml`` lists the available catalog versions and the default. A
migration file ``catalog/owasp-mcp/migrations/<from>__to__<to>.yaml`` maps every risk ID of one
version to its ID in another (or ``null`` when the risk is retired).

Scanner checks declare risk IDs in the default version's numbering. For any other version they are
translated through the migration from the default version, so findings, coverage, and crosswalk
validation all use the selected version's IDs.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from mcp_crosswalk import resources
from mcp_crosswalk.checks.base import Check
from mcp_crosswalk.checks.registry import ALL_CHECKS
from mcp_crosswalk.models import CatalogVersion, CatalogVersions, Migration, OwaspCatalog

VERSIONS_FILE = "versions.yaml"
MIGRATIONS_DIR = "migrations"


class VersionError(ValueError):
    """A catalog version, the versions file, or a migration file is unusable."""


class UnknownVersionError(VersionError):
    def __init__(self, version: str, available: list[str]) -> None:
        super().__init__(
            f"unknown OWASP catalog version {version!r}; available: {', '.join(available)}"
        )
        self.version = version
        self.available = available


@dataclass(frozen=True)
class ResolvedVersion:
    info: CatalogVersion
    catalog_path: Path
    crosswalk_dir: Path | None

    @property
    def id(self) -> str:
        return self.info.id


def _read_yaml(path: Path) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise VersionError(f"cannot read {path.name}: {exc}") from exc


def load_versions() -> CatalogVersions:
    """Load and check ``versions.yaml`` (unique IDs; the default is listed)."""
    try:
        versions = CatalogVersions.model_validate(_read_yaml(resources.owasp_dir() / VERSIONS_FILE))
    except ValidationError as exc:
        raise VersionError(f"{VERSIONS_FILE} is invalid: {exc.error_count()} error(s)") from exc
    ids = [v.id for v in versions.versions]
    if len(ids) != len(set(ids)):
        raise VersionError(f"{VERSIONS_FILE} lists a version more than once")
    if versions.default not in ids:
        raise VersionError(f"{VERSIONS_FILE}: default {versions.default!r} is not listed")
    return versions


def available_versions() -> list[str]:
    return [v.id for v in load_versions().versions]


def default_version() -> str:
    return load_versions().default


def resolve(version: str | None = None) -> ResolvedVersion:
    """Resolve a version ID (None means the default). Raises UnknownVersionError if not listed."""
    versions = load_versions()
    wanted = versions.default if version is None else version.strip()
    for info in versions.versions:
        if info.id == wanted:
            crosswalk = resources.data_root() / info.crosswalk if info.crosswalk else None
            return ResolvedVersion(info, resources.owasp_dir() / info.file, crosswalk)
    raise UnknownVersionError(wanted, [v.id for v in versions.versions])


def load_owasp(version: str | None = None) -> OwaspCatalog:
    """Load the OWASP catalog for a version; its ``version`` field must equal the version ID."""
    resolved = resolve(version)
    try:
        catalog = OwaspCatalog.model_validate(_read_yaml(resolved.catalog_path))
    except ValidationError as exc:
        raise VersionError(
            f"{resolved.info.file} is invalid: {exc.error_count()} error(s)"
        ) from exc
    if catalog.version != resolved.id:
        raise VersionError(
            f"{resolved.info.file}: version {catalog.version!r} does not match "
            f"versions.yaml id {resolved.id!r}"
        )
    return catalog


def migration_path(from_version: str, to_version: str) -> Path:
    return resources.owasp_dir() / MIGRATIONS_DIR / f"{from_version}__to__{to_version}.yaml"


def migration_problems(
    migration: Migration, source: OwaspCatalog, target: OwaspCatalog
) -> list[str]:
    """Check a migration against both catalogs. Returns a list of problems (empty when valid)."""
    problems = []
    if migration.from_version != source.version:
        problems.append(f"from_version {migration.from_version!r} is not {source.version!r}")
    if migration.to_version != target.version:
        problems.append(f"to_version {migration.to_version!r} is not {target.version!r}")
    source_ids = {r.short_id for r in source.risks}
    target_ids = {r.short_id for r in target.risks}
    for old in sorted(source_ids - set(migration.map)):
        problems.append(f"map has no entry for {old} (list it, with to: null if retired)")
    for old in sorted(set(migration.map) - source_ids):
        problems.append(f"map key {old} is not a risk in {source.version}")
    seen: dict[str, str] = {}
    for old, entry in sorted(migration.map.items()):
        if entry.to is None:
            continue
        if entry.to not in target_ids:
            problems.append(f"{old} -> {entry.to}: {entry.to} is not a risk in {target.version}")
        if entry.to in seen:
            problems.append(
                f"{old} and {seen[entry.to]} both map to {entry.to}; "
                "merges must be authored by hand"
            )
        seen[entry.to] = old
    return problems


def load_migration(from_version: str, to_version: str) -> Migration:
    """Load and validate the migration between two listed versions."""
    path = migration_path(from_version, to_version)
    if not path.is_file():
        raise VersionError(f"no migration file {MIGRATIONS_DIR}/{path.name}")
    try:
        migration = Migration.model_validate(_read_yaml(path))
    except ValidationError as exc:
        raise VersionError(f"{path.name} is invalid: {exc.error_count()} error(s)") from exc
    problems = migration_problems(migration, load_owasp(from_version), load_owasp(to_version))
    if problems:
        raise VersionError(f"{path.name} is invalid: " + "; ".join(problems))
    return migration


def risk_translation(version: str | None = None) -> dict[str, str | None]:
    """Map each default-version risk ID to its ID in ``version`` (None when retired).

    Without a migration file, IDs carry over unchanged, but only if every default-version ID still
    exists in the target catalog.
    """
    target = resolve(version).id
    default = default_version()
    default_ids = sorted(r.short_id for r in load_owasp(default).risks)
    if target == default:
        return {risk: risk for risk in default_ids}
    if migration_path(default, target).is_file():
        return {old: entry.to for old, entry in load_migration(default, target).map.items()}
    target_ids = {r.short_id for r in load_owasp(target).risks}
    missing = [risk for risk in default_ids if risk not in target_ids]
    if missing:
        raise VersionError(
            f"no migration from {default} to {target}, and {', '.join(missing)} "
            f"do not exist in {target}"
        )
    return {risk: risk for risk in default_ids}


def checks_for(version: str | None = None) -> tuple[Check, ...]:
    """The registered checks with risk IDs translated into ``version``'s numbering."""
    translation = risk_translation(version)
    translated = []
    for check in ALL_CHECKS:
        risks = tuple(
            new for new in (translation.get(r, r) for r in check.risk_ids) if new is not None
        )
        translated.append(dataclasses.replace(check, risk_ids=risks))
    return tuple(translated)


def check_risk_index_for(version: str | None = None) -> dict[str, tuple[str, ...]]:
    return {check.id: check.risk_ids for check in checks_for(version)}
