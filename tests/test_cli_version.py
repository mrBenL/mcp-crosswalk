from typer.testing import CliRunner

from mcp_crosswalk import __version__
from mcp_crosswalk.cli import app


def test_version_prints_package_version() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.2.0"
    assert __version__ == "0.2.0"
