"""Combo rule evaluator for seccompute.

Detects emergent risks from syscall combinations — cases where two or more
syscalls together enable an attack that neither could achieve alone, or where
a syscall family (e.g. io_uring) bypasses controls on traditional equivalents.

Usage:
    from .combos import evaluate_combos, ComboFinding
    findings = evaluate_combos(profile, syscall_states)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_COMBO_RULES_PATH = Path(__file__).parent / "combo_rules.yaml"
_cached_combos: list[dict[str, Any]] | None = None


def _load_combos() -> list[dict[str, Any]]:
    global _cached_combos
    if _cached_combos is not None:
        return _cached_combos
    with open(_COMBO_RULES_PATH, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    _cached_combos = raw.get("combos", [])
    return _cached_combos


@dataclass
class ComboFinding:
    """A triggered combo rule finding.

    Attributes:
        id: Combo rule identifier.
        name: Short human-readable name.
        description: What the combination enables.
        triggered_by: Which syscalls from the rule were found allowed.
        bypasses_blocked: Subset of bypassed syscalls actually blocked in profile.
        severity: HIGH | MEDIUM | LOW.
        references: CVE IDs, technique IDs, or URLs.
    """
    id: str
    name: str
    description: str
    triggered_by: list[str]
    bypasses_blocked: list[str]
    severity: str
    references: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        blocked = ", ".join(self.bypasses_blocked) if self.bypasses_blocked else "none currently blocked"
        return (
            f"{self.name}: {', '.join(self.triggered_by)} allowed — "
            f"bypasses blocked syscalls: [{blocked}]"
        )


def _is_allowed(syscall: str, states: dict[str, str]) -> bool:
    """Return True if a syscall is allowed or conditionally allowed."""
    return states.get(syscall, "blocked") in ("allowed", "conditional")


def evaluate_combos(
    profile: dict,
    syscall_states: dict[str, str],
) -> list[ComboFinding]:
    """Evaluate all combo rules against a profile's resolved syscall states.

    Args:
        profile: OCI seccomp profile dict (used to check defaultAction).
        syscall_states: Mapping of syscall name -> "blocked"|"conditional"|"allowed".
                        Should cover all dangerous syscalls plus any profile syscalls.

    Returns:
        List of ComboFinding for each triggered combo rule.
    """
    combos = _load_combos()
    findings: list[ComboFinding] = []

    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    permissive_default = default_action in {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}

    def effective_state(sc: str) -> str:
        if sc in syscall_states:
            return syscall_states[sc]
        return "allowed" if permissive_default else "blocked"

    for rule in combos:
        syscalls = rule.get("syscalls", [])
        trigger = rule.get("trigger", "all_allowed")
        bypasses = rule.get("bypasses", [])
        requires_blocked = rule.get("bypass_requires_blocked", False)

        # Determine which trigger syscalls are allowed
        allowed_triggers = [sc for sc in syscalls if _is_allowed(sc, {sc: effective_state(sc)})]

        triggered = False
        if trigger == "all_allowed":
            triggered = len(allowed_triggers) == len(syscalls)
        elif trigger == "any_allowed":
            triggered = len(allowed_triggers) > 0
        elif trigger == "gate_allowed":
            triggered = bool(syscalls) and _is_allowed(syscalls[0], {syscalls[0]: effective_state(syscalls[0])})

        if not triggered:
            continue

        # Find which bypassed syscalls are actually blocked in this profile
        bypasses_blocked = [
            sc for sc in bypasses
            if effective_state(sc) == "blocked"
        ]

        # If bypass_requires_blocked, only fire when at least one bypassed syscall is blocked
        if requires_blocked and not bypasses_blocked:
            continue

        findings.append(ComboFinding(
            id=rule.get("id", "COMBO-unknown"),
            name=rule.get("name", ""),
            description=rule.get("description", "").strip(),
            triggered_by=allowed_triggers,
            bypasses_blocked=sorted(bypasses_blocked),
            severity=rule.get("severity", "MEDIUM"),
            references=rule.get("references", []),
        ))

    return findings
