"""Verify a built wheel ships its data and that the packaged code finds that data.

Usage (after `uv build`), from the project root:

    uv run python -I scripts/check_wheel.py dist/mcp_crosswalk-0.2.0-py3-none-any.whl <empty dir>

The wheel is extracted into that directory and imported from there (ahead of the editable dev
install), so `importlib.resources` lookups run against the wheel's own files. Nothing is installed.
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

_FRAMEWORKS = "mcp_crosswalk/data/catalog/frameworks"
REQUIRED = [
    "mcp_crosswalk/reporters/templates/report.html.j2",
    "mcp_crosswalk/data/catalog/owasp-mcp/2025-beta.yaml",
    "mcp_crosswalk/data/catalog/owasp-mcp/versions.yaml",
    "mcp_crosswalk/data/catalog/owasp-mcp/migrations/README.md",
    f"{_FRAMEWORKS}/SOURCES.md",
    f"{_FRAMEWORKS}/nist-800-53r5/NIST_SP-800-53_rev5_catalog.json",
    f"{_FRAMEWORKS}/nist-csf-2.0/NIST_CSF_v2.0_catalog.json",
    *[
        f"{_FRAMEWORKS}/nist-800-53r5-baselines/"
        f"NIST_SP-800-53_rev5_{name}-baseline-resolved-profile_catalog.json"
        for name in ("LOW", "MODERATE", "HIGH", "PRIVACY")
    ],
    f"{_FRAMEWORKS}/nist-800-171r3/NIST_SP800-171_rev3_catalog.json",
    "mcp_crosswalk/data/schema/report.schema.json",
    "mcp_crosswalk/data/schema/crosswalk.schema.json",
    "mcp_crosswalk/data/schema/migration.schema.json",
    "mcp_crosswalk/data/schema/versions.schema.json",
    *[f"mcp_crosswalk/data/crosswalk/MCP{n:02d}.yaml" for n in range(1, 11)],
]
SARIF_PROBE = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "probe"}}, "results": [{"ruleId": "MCP01"}]}],
}


def fail(message: str) -> None:
    print(f"WHEEL CHECK FAILED: {message}")
    sys.exit(1)


def main() -> None:
    wheel, extract_to = Path(sys.argv[1]), Path(sys.argv[2]).resolve()
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        missing = [r for r in REQUIRED if r not in names]
        licenses = sorted(n for n in names if n.endswith(("LICENSE", "LICENSE-DATA.md", "NOTICE")))
        print(f"wheel entries: {len(names)}; missing required: {missing}; licenses: {licenses}")
        if missing:
            fail(f"missing files: {missing}")
        archive.extractall(extract_to)

    sys.path.insert(0, str(extract_to))
    import mcp_crosswalk
    from mcp_crosswalk.resources import data_root

    package_file = Path(mcp_crosswalk.__file__).resolve()
    root = data_root().resolve()
    print(f"package imported from: {package_file}")
    print(f"data_root():           {root}")
    if extract_to not in package_file.parents:
        fail("imported the development copy, not the wheel")
    if extract_to not in root.parents:
        fail("data resolved outside the wheel")

    from typer.testing import CliRunner

    from mcp_crosswalk import federal, versions
    from mcp_crosswalk.cli import app

    available, default = versions.available_versions(), versions.default_version()
    print(f"catalog versions: {available} (default {default})")
    if federal.baselines_for("nist-800-53r5", "AC-2") != ["LOW", "MODERATE", "HIGH"]:
        fail("baseline data did not load from the wheel")
    if "03.05.07" not in federal.sp800_171r3_for("nist-800-53r5", "IA-5(1)"):
        fail("800-171r3 data did not load from the wheel")
    print("federal data: baselines and 800-171r3 links load from the wheel")

    runner = CliRunner()
    result = runner.invoke(app, ["crosswalk", "validate"])
    print(f"crosswalk validate: exit {result.exit_code}: {result.output.strip()}")
    if result.exit_code != 0:
        fail("crosswalk validate did not succeed from the wheel")

    config = extract_to / "probe.json"
    config.write_text('{"mcpServers": {"s": {"command": "node", "args": ["s.js"]}}}', "utf-8")
    out = extract_to / "out"
    formats = "json,md,html,sarif,poam"
    args = ["scan", "--config", str(config), "--format", formats, "--out", str(out)]
    result = runner.invoke(app, args)
    produced = sorted(p.name for p in out.iterdir()) if out.is_dir() else []
    print(f"scan: exit {result.exit_code}; reports {produced}")
    if result.exit_code != 0 or len(produced) != 5:
        fail("scan from the wheel did not produce five reports")

    sarif = extract_to / "probe.sarif"
    sarif.write_text(json.dumps(SARIF_PROBE), "utf-8")
    enrich_out = extract_to / "enrich-out"
    args = ["enrich", str(sarif), "--format", "sarif,json,md", "--out", str(enrich_out)]
    result = runner.invoke(app, args)
    produced = sorted(p.name for p in enrich_out.iterdir()) if enrich_out.is_dir() else []
    print(f"enrich: exit {result.exit_code}; outputs {produced}")
    if result.exit_code != 0 or len(produced) != 3:
        fail("enrich from the wheel did not produce three outputs")
    print("WHEEL OK")


if __name__ == "__main__":
    main()
