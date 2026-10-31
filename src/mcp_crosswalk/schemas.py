"""Export JSON Schemas for the crosswalk file format and the scan report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mcp_crosswalk.models import CatalogVersions, CrosswalkFile, Migration, Report

SCHEMAS: dict[str, tuple[type[BaseModel], str]] = {
    "crosswalk.schema.json": (CrosswalkFile, "mcp-crosswalk crosswalk file"),
    "report.schema.json": (Report, "mcp-crosswalk scan report"),
    "migration.schema.json": (Migration, "mcp-crosswalk OWASP catalog risk ID migration"),
    "versions.schema.json": (CatalogVersions, "mcp-crosswalk OWASP catalog versions"),
}


def build_schema(model: type[BaseModel], title: str) -> dict[str, Any]:
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = title
    return schema


def render_schemas() -> dict[str, str]:
    """Return ``{filename: json text}`` for every exported schema."""
    return {
        filename: json.dumps(build_schema(model, title), indent=2, sort_keys=True) + "\n"
        for filename, (model, title) in SCHEMAS.items()
    }


def export_schemas(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, text in render_schemas().items():
        target = out_dir / filename
        target.write_text(text, encoding="utf-8")
        written.append(target)
    return written
