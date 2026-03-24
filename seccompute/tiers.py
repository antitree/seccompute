"""Tier classification and weight computation.

Derives tier membership and per-syscall weights from syscall_rules.yaml.
"""
from __future__ import annotations

from typing import Any

# Budget allocations summing to 100
TIER_BUDGETS: dict[int, float] = {
    1: 85.0,
    2: 10.0,
    3: 5.0,
}


def build_tiers(syscall_rules: dict[str, Any]) -> dict[int, list[str]]:
    """Group syscalls by tier from loaded rules.

    Returns {tier_number: [syscall_names]}.
    """
    tiers: dict[int, list[str]] = {}
    for name, entry in syscall_rules.items():
        t = entry.get("tier", 0)
        if t > 0:
            tiers.setdefault(t, []).append(name)
    return tiers


def build_weights(tiers: dict[int, list[str]]) -> dict[str, float]:
    """Compute per-syscall weight = tier_budget / count(tier_members).

    Returns {syscall_name: weight}.
    """
    weights: dict[str, float] = {}
    for tier_num, members in tiers.items():
        budget = TIER_BUDGETS.get(tier_num, 0.0)
        if not members:
            continue
        per_syscall = budget / len(members)
        for name in members:
            weights[name] = per_syscall
    return weights


def get_all_dangerous(tiers: dict[int, list[str]]) -> frozenset[str]:
    """Return frozenset of all dangerous syscall names across all tiers."""
    result: set[str] = set()
    for members in tiers.values():
        result.update(members)
    return frozenset(result)
