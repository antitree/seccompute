"""Combo rule evaluator for seccompute.

Detects emergent risks from syscall combinations.
"""
from __future__ import annotations

from typing import Any

from .model import ComboFinding

# Actions that let a syscall through
_PERMISSIVE = {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}


def _is_allowed(syscall: str, states: dict[str, str]) -> bool:
    """Return True if a syscall is allowed or conditionally allowed."""
    return states.get(syscall, "blocked") in ("allowed", "conditional")


def evaluate_combos(
    profile: dict,
    syscall_states: dict[str, str],
    combo_rules: list[dict[str, Any]],
) -> list[ComboFinding]:
    """Evaluate all combo rules against resolved syscall states.

    Args:
        profile: OCI seccomp profile dict (for defaultAction).
        syscall_states: syscall -> "blocked"|"conditional"|"allowed".
        combo_rules: Loaded combo rules from YAML.

    Returns:
        List of ComboFinding for each triggered combo rule.
    """
    findings: list[ComboFinding] = []

    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    permissive_default = default_action in _PERMISSIVE

    def effective_state(sc: str) -> str:
        if sc in syscall_states:
            return syscall_states[sc]
        return "allowed" if permissive_default else "blocked"

    for rule in combo_rules:
        syscalls = rule.get("syscalls", [])
        trigger = rule.get("trigger", "all_allowed")
        bypasses = rule.get("bypasses", [])
        requires_blocked = rule.get("bypass_requires_blocked", False)

        # Determine which trigger syscalls are allowed
        allowed_triggers = [
            sc for sc in syscalls
            if _is_allowed(sc, {sc: effective_state(sc)})
        ]

        triggered = False
        if trigger == "all_allowed":
            triggered = len(allowed_triggers) == len(syscalls) and len(syscalls) > 0
        elif trigger == "any_allowed":
            triggered = len(allowed_triggers) > 0
        elif trigger == "gate_allowed":
            triggered = bool(syscalls) and _is_allowed(
                syscalls[0], {syscalls[0]: effective_state(syscalls[0])}
            )

        if not triggered:
            continue

        # Find which bypassed syscalls are actually blocked
        bypasses_blocked = [
            sc for sc in bypasses
            if effective_state(sc) == "blocked"
        ]

        if requires_blocked and not bypasses_blocked:
            continue

        findings.append(ComboFinding(
            id=rule.get("id", "COMBO-unknown"),
            name=rule.get("name", ""),
            description=rule.get("description", "").strip(),
            severity=rule.get("severity", "MEDIUM"),
            triggered_by=allowed_triggers,
            bypasses_blocked=sorted(bypasses_blocked),
            references=rule.get("references", []),
        ))

    return findings
