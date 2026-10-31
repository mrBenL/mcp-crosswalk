"""Static interpretation of stdio launch commands (npx, uvx, docker, shells).

Nothing here executes anything; it only reads the command and argument strings from the config.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_WINDOWS_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1")

# docker/podman `run` options that take a separate value argument.
_DOCKER_VALUE_FLAGS = frozenset(
    {
        "-a",
        "--attach",
        "--add-host",
        "--cap-add",
        "--cap-drop",
        "--cgroupns",
        "--cidfile",
        "--cpus",
        "--cpu-shares",
        "-c",
        "--device",
        "--dns",
        "-e",
        "--env",
        "--env-file",
        "--entrypoint",
        "--gpus",
        "-h",
        "--hostname",
        "--ipc",
        "-l",
        "--label",
        "--log-driver",
        "--log-opt",
        "-m",
        "--memory",
        "--mount",
        "--name",
        "--net",
        "--network",
        "-p",
        "--publish",
        "--pid",
        "--platform",
        "--pull",
        "--restart",
        "--runtime",
        "--security-opt",
        "--stop-signal",
        "--tmpfs",
        "-u",
        "--user",
        "--ulimit",
        "--userns",
        "--uts",
        "-v",
        "--volume",
        "--volumes-from",
        "-w",
        "--workdir",
    }
)
_NPX_VALUE_FLAGS = frozenset({"-p", "--package", "-c", "--call", "--registry", "--cache"})
_UVX_VALUE_FLAGS = frozenset(
    {"--from", "--with", "-w", "--python", "-p", "--index", "--index-url", "--extra-index-url"}
)
_PIPX_VALUE_FLAGS = frozenset({"--spec", "--python", "--index-url", "--pip-args"})


def basename(command: str | None) -> str:
    """Lowercase executable name without directory or Windows suffix."""
    if not command:
        return ""
    name = re.split(r"[\\/]", command.strip())[-1].lower()
    for suffix in _WINDOWS_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _first_positional(args: list[str], value_flags: frozenset[str]) -> tuple[int, str] | None:
    skip = False
    for index, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg == "--":
            return (index + 1, args[index + 1]) if index + 1 < len(args) else None
        if arg.startswith("-"):
            if "=" not in arg and arg in value_flags:
                skip = True
            continue
        return index, arg
    return None


def _flag_value(args: list[str], names: frozenset[str]) -> str | None:
    for index, arg in enumerate(args):
        flag, sep, value = arg.partition("=")
        if flag in names:
            if sep:
                return value
            if index + 1 < len(args):
                return args[index + 1]
    return None


@dataclass(frozen=True)
class PackageLaunch:
    """A package fetched and run by a launcher at server start."""

    ecosystem: str  # "npm", "pypi", or "container"
    launcher: str  # npx, bunx, pnpm dlx, uvx, pipx run, docker run, podman run
    spec: str  # package spec as written, e.g. "@scope/pkg@1.2.3"
    args: tuple[str, ...]  # launcher arguments (after "dlx"/"run" where applicable)


def package_launch(command: str | None, args: list[str]) -> PackageLaunch | None:
    """Identify the package a stdio launch command fetches, if any."""
    exe = basename(command)
    if exe in {"npx", "bunx"}:
        package = _flag_value(args, frozenset({"-p", "--package"}))
        found = _first_positional(args, _NPX_VALUE_FLAGS)
        spec = package or (found[1] if found else None)
        return PackageLaunch("npm", exe, spec, tuple(args)) if spec else None
    if exe == "pnpm" and args[:1] == ["dlx"]:
        rest = args[1:]
        found = _first_positional(rest, _NPX_VALUE_FLAGS)
        return PackageLaunch("npm", "pnpm dlx", found[1], tuple(rest)) if found else None
    if exe == "uvx" or (exe == "uv" and args[:2] == ["tool", "run"]):
        rest = args if exe == "uvx" else args[2:]
        source = _flag_value(rest, frozenset({"--from"}))
        found = _first_positional(rest, _UVX_VALUE_FLAGS)
        spec = source or (found[1] if found else None)
        return PackageLaunch("pypi", "uvx", spec, tuple(rest)) if spec else None
    if exe == "pipx" and args[:1] == ["run"]:
        rest = args[1:]
        source = _flag_value(rest, frozenset({"--spec"}))
        found = _first_positional(rest, _PIPX_VALUE_FLAGS)
        spec = source or (found[1] if found else None)
        return PackageLaunch("pypi", "pipx run", spec, tuple(rest)) if spec else None
    run_args = container_run_args(command, args)
    if run_args is not None:
        found = _first_positional(run_args, _DOCKER_VALUE_FLAGS)
        if found is None:
            return None
        return PackageLaunch("container", f"{exe} run", found[1], tuple(run_args))
    return None


def container_run_args(command: str | None, args: list[str]) -> list[str] | None:
    """Arguments after ``run`` for ``docker run`` / ``podman run`` (or ``container run``)."""
    exe = basename(command)
    if exe not in {"docker", "podman"}:
        return None
    if args[:1] == ["run"]:
        return args[1:]
    if args[:2] == ["container", "run"]:
        return args[2:]
    return None


def container_run_options(command: str | None, args: list[str]) -> list[str] | None:
    """``docker run`` / ``podman run`` options only: everything before the image name.

    Arguments after the image belong to the container's own process, not to the runtime.
    """
    run_args = container_run_args(command, args)
    if run_args is None:
        return None
    found = _first_positional(run_args, _DOCKER_VALUE_FLAGS)
    return run_args[: found[0]] if found else run_args


_NPM_RANGE = re.compile(r"[\^~*<>|]|(?:^|\.)[xX](?:\.|$)|\s-\s|^\d+$|^\d+\.\d+$")
_NPM_EXACT_START = re.compile(r"^v?\d")


def _is_local_or_vcs(spec: str) -> bool:
    return bool(re.match(r"^(?:\.{0,2}/|[A-Za-z]:[\\/]|file:|git\+|https?://|github:)", spec))


def npm_version(spec: str) -> str | None:
    """Version part of an npm spec (``@scope/name@1.0`` -> ``1.0``), or None."""
    body = spec[1:] if spec.startswith("@") else spec
    if "@" not in body:
        return None
    return body.rsplit("@", 1)[1]


def npm_name(spec: str) -> str:
    body = spec[1:] if spec.startswith("@") else spec
    name = body.rsplit("@", 1)[0] if "@" in body else body
    return ("@" + name) if spec.startswith("@") else name


def pypi_name(spec: str) -> str:
    return re.split(r"[=<>!~@\[ ;]", spec, maxsplit=1)[0]


def image_name(spec: str) -> str:
    base = spec.split("@", 1)[0]
    last = base.rsplit("/", 1)[-1]
    if ":" in last:
        base = base[: len(base) - len(last)] + last.split(":", 1)[0]
    return base


def unpinned_reason(launch: PackageLaunch) -> str | None:
    """Why a package launch is not pinned to an exact version, or None if it is pinned."""
    spec = launch.spec.strip()
    if launch.ecosystem == "npm":
        if _is_local_or_vcs(spec):
            return None
        version = npm_version(spec)
        if version is None or version == "":
            return "no version"
        if version.lower() == "latest":
            return "@latest"
        if _NPM_RANGE.search(version):
            return f"version range @{version}"
        if not _NPM_EXACT_START.match(version):
            return f"dist-tag @{version}"
        return None
    if launch.ecosystem == "pypi":
        if _is_local_or_vcs(spec) and "@" in spec.split("://", 1)[-1]:
            return None
        if "==" in spec:
            return None
        if "@" in spec:
            version = spec.rsplit("@", 1)[1]
            return "@latest" if version.lower() == "latest" else None
        return "no version"
    # Container image: pinned by digest, or by an explicit non-latest tag.
    if "@sha256:" in spec:
        return None
    last = spec.rsplit("/", 1)[-1]
    if ":" not in last:
        return "no tag"
    if last.rsplit(":", 1)[1].lower() == "latest":
        return ":latest"
    return None


def package_name(launch: PackageLaunch) -> str:
    if launch.ecosystem == "npm":
        return npm_name(launch.spec)
    if launch.ecosystem == "pypi":
        return pypi_name(launch.spec)
    return image_name(launch.spec)
