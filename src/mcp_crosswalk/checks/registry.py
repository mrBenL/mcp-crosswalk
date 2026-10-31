"""Registry of all static checks, in ID order."""

from __future__ import annotations

from mcp_crosswalk.checks import (
    allowlist,
    auto_install,
    broad_fs_scope,
    cleartext_launcher,
    cleartext_remote,
    privileged_container,
    remote_no_auth,
    secrets_args,
    secrets_env,
    shell_inline,
    unpinned_packages,
)
from mcp_crosswalk.checks.base import Check

ALL_CHECKS: tuple[Check, ...] = tuple(
    sorted(
        (
            secrets_env.CHECK,
            secrets_args.CHECK,
            unpinned_packages.CHECK,
            auto_install.CHECK,
            shell_inline.CHECK,
            broad_fs_scope.CHECK,
            cleartext_remote.CHECK,
            remote_no_auth.CHECK,
            allowlist.CHECK,
            privileged_container.CHECK,
            cleartext_launcher.CHECK,
        ),
        key=lambda c: c.id,
    )
)


def get_registry() -> dict[str, Check]:
    """Return ``{check_id: Check}`` for every registered check."""
    registry: dict[str, Check] = {}
    for check in ALL_CHECKS:
        if check.id in registry:
            raise ValueError(f"duplicate check id {check.id}")
        registry[check.id] = check
    return registry


def check_risk_index() -> dict[str, tuple[str, ...]]:
    """Return ``{check_id: risk_ids}`` for every registered check."""
    return {check.id: check.risk_ids for check in ALL_CHECKS}
