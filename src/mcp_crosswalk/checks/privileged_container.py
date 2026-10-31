"""MCPXW-010: container launch with excessive privilege."""

from __future__ import annotations

import re

from mcp_crosswalk.checks.base import Check, CheckContext, make_finding
from mcp_crosswalk.checks.broad_fs_scope import is_broad_path
from mcp_crosswalk.checks.launch import basename, container_run_options
from mcp_crosswalk.models import Finding, ServerEntry
from mcp_crosswalk.redact import redact_known_tokens

_DANGEROUS_CAPS = frozenset({"all", "sys_admin", "cap_sys_admin"})


def _option_values(args: list[str], names: tuple[str, ...]) -> list[tuple[int, str]]:
    values = []
    for index, arg in enumerate(args):
        for name in names:
            if arg == name and index + 1 < len(args):
                values.append((index, args[index + 1]))
            elif arg.startswith(name + "="):
                values.append((index, arg[len(name) + 1 :]))
    return values


def _mount_source(volume: str) -> str:
    """Host side of a ``-v`` value (``src:dst[:opts]``), keeping a Windows drive letter."""
    if re.match(r"^[A-Za-z]:[\\/]", volume):
        rest = volume[2:]
        return volume[:2] + rest.split(":", 1)[0]
    return volume.split(":", 1)[0]


def _mount_flag_source(spec: str) -> str | None:
    for field in spec.split(","):
        key, _, value = field.partition("=")
        if key.strip().lower() in {"source", "src"}:
            return value.strip()
    return None


def _is_sensitive_mount(source: str) -> str | None:
    lowered = source.lower()
    if "docker.sock" in lowered or "podman.sock" in lowered or "containerd.sock" in lowered:
        return "container runtime socket"
    if is_broad_path(source):
        return "root or home directory"
    return None


def run(check: Check, entry: ServerEntry, _context: CheckContext) -> list[Finding]:
    run_args = container_run_options(entry.command, entry.args)
    if run_args is None:
        return []
    runtime = basename(entry.command)
    issues: list[tuple[str, str]] = []
    for arg in run_args:
        if arg == "--privileged" or arg.lower() == "--privileged=true":
            issues.append(("privileged", "--privileged"))
    for _, value in _option_values(run_args, ("--pid",)):
        if value.lower() == "host":
            issues.append(("pid", "--pid=host"))
    for _, value in _option_values(run_args, ("--network", "--net")):
        if value.lower() == "host":
            issues.append(("network", "--network=host"))
    for _, value in _option_values(run_args, ("--cap-add",)):
        if value.lower() in _DANGEROUS_CAPS:
            issues.append((f"cap:{value.lower()}", f"--cap-add={value}"))
    for _, value in _option_values(run_args, ("-v", "--volume")):
        source = _mount_source(value)
        reason = _is_sensitive_mount(source)
        if reason:
            issues.append((f"volume:{source}", f"volume {redact_known_tokens(value)} ({reason})"))
    for _, value in _option_values(run_args, ("--mount",)):
        flag_source = _mount_flag_source(value)
        flag_reason = _is_sensitive_mount(flag_source) if flag_source else None
        if flag_source and flag_reason:
            detail = f"--mount {redact_known_tokens(value)} ({flag_reason})"
            issues.append((f"mount:{flag_source}", detail))
    findings = []
    for key, detail in issues:
        evidence = f"{runtime} run {detail}"
        findings.append(make_finding(check, entry, f"container:{key}", evidence))
    return findings


CHECK = Check(
    id="MCPXW-010",
    title="Container launch with excessive privilege",
    risk_ids=("MCP02", "MCP05"),
    severity="high",
    description=(
        "Flags docker or podman run launches that remove container isolation: --privileged, "
        "--pid=host, --network=host, --cap-add=ALL or SYS_ADMIN, or a bind mount of the filesystem "
        "root, a home directory, or the container runtime socket (which grants control of the "
        "host)."
    ),
    remediation=(
        "Run the MCP server container unprivileged with default namespaces, drop capabilities it "
        "does not need, mount only the specific directories it requires (read-only where "
        "possible), and never mount the Docker or Podman socket into an MCP server."
    ),
    run_fn=run,
)
