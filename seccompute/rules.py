"""YAML-based syscall rule loader for seccompute.

Loads syscall threat data from syscall_rules.yaml and provides
lookup functions for tier assignments, rule details, and the
complete rule set.

Rules are loaded once and cached for the lifetime of the process.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_RULES_PATH = Path(__file__).parent / "syscall_rules.yaml"

# Module-level cache
_cached_rules: dict[str, dict[str, Any]] | None = None


def _load_rules() -> dict[str, dict[str, Any]]:
    """Load and cache rules from the YAML file.

    Returns:
        Dict mapping syscall name to its rule definition.
    """
    global _cached_rules
    if _cached_rules is not None:
        return _cached_rules

    with open(_RULES_PATH, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Expected YAML dict, got {type(raw).__name__}")

    _cached_rules = raw
    return _cached_rules


def get_all_rules() -> dict[str, dict[str, Any]]:
    """Return the complete mapping of syscall name to rule definition.

    Each rule contains: tier, category, description, threats, last_reviewed,
    and optionally notes.
    """
    return dict(_load_rules())


def get_rule(syscall: str) -> dict[str, Any] | None:
    """Return the rule definition for a specific syscall, or None if unknown.

    Args:
        syscall: The syscall name (e.g., "ptrace", "bpf").

    Returns:
        Rule dict with tier, category, description, threats, etc., or None.
    """
    return _load_rules().get(syscall)


def get_tier(syscall: str) -> int:
    """Return the tier (1, 2, or 3) for a syscall, or 0 if not in rules.

    Args:
        syscall: The syscall name.

    Returns:
        Integer tier (1-3) or 0 for unknown syscalls.
    """
    rule = get_rule(syscall)
    if rule is None:
        return 0
    return rule.get("tier", 0)
