"""Locate packaged data (crosswalk, catalogs, schemas).

In a built wheel the data is shipped inside the package at ``mcp_crosswalk/data/`` and found via
``importlib.resources``. In a source checkout (editable install) the same directories live at the
repository root, so we fall back to that only when the packaged copy is absent.
"""

from __future__ import annotations

import importlib.resources
from functools import cache
from pathlib import Path


class DataNotFoundError(RuntimeError):
    """Raised when the packaged data directory cannot be located."""


def _has_data(root: Path) -> bool:
    return (root / "crosswalk").is_dir() and (root / "catalog").is_dir()


@cache
def data_root() -> Path:
    """Return the directory that contains ``crosswalk/``, ``catalog/`` and ``schema/``."""
    packaged = Path(str(importlib.resources.files("mcp_crosswalk") / "data"))
    if _has_data(packaged):
        return packaged
    source_checkout = Path(__file__).resolve().parents[2]
    if _has_data(source_checkout):
        return source_checkout
    raise DataNotFoundError("mcp-crosswalk data files not found; the installation looks incomplete")


def crosswalk_dir() -> Path:
    return data_root() / "crosswalk"


def owasp_dir() -> Path:
    return data_root() / "catalog" / "owasp-mcp"


def owasp_catalog_path() -> Path:
    """The 2025-beta catalog file. Prefer ``versions.resolve()`` for version-aware lookups."""
    return owasp_dir() / "2025-beta.yaml"


def frameworks_dir() -> Path:
    return data_root() / "catalog" / "frameworks"


def schema_dir() -> Path:
    return data_root() / "schema"
