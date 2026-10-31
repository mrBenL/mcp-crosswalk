import json
from pathlib import Path

import jsonschema
import yaml
from typer.testing import CliRunner

from mcp_crosswalk.cli import app
from mcp_crosswalk.resources import crosswalk_dir
from mcp_crosswalk.schemas import render_schemas

REPO = Path(__file__).resolve().parent.parent


def test_committed_schemas_are_current() -> None:
    for filename, text in render_schemas().items():
        committed = (REPO / "schema" / filename).read_text(encoding="utf-8")
        assert committed == text, f"schema/{filename} is stale; run `mcpxw schema export`"


def test_crosswalk_files_validate_against_exported_schema() -> None:
    schema = json.loads(render_schemas()["crosswalk.schema.json"])
    for path in sorted(crosswalk_dir().glob("*.yaml")):
        jsonschema.validate(yaml.safe_load(path.read_text(encoding="utf-8")), schema)


def test_crosswalk_schema_rejects_unknown_keys() -> None:
    schema = json.loads(render_schemas()["crosswalk.schema.json"])
    doc = yaml.safe_load((crosswalk_dir() / "MCP01.yaml").read_text(encoding="utf-8"))
    doc["extra"] = True
    validator = jsonschema.Draft202012Validator(schema)
    assert list(validator.iter_errors(doc))


def test_cli_schema_export(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["schema", "export", "--out", str(tmp_path)])
    assert result.exit_code == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "crosswalk.schema.json",
        "migration.schema.json",
        "report.schema.json",
        "versions.schema.json",
    ]
