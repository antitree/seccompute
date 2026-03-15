"""Conditional analysis for seccomp profile rules.

Detects and classifies conditionals in seccomp rules:
- Capability gates (includes.caps / excludes.caps)
- Argument filters (args)
- Kernel version gates (includes.minKernel)
- Architecture filters (includes.arches)

Used by the scoring engine to apply conditional multipliers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConditionalNote:
    """Record of a conditional interpretation applied during scoring.

    Attributes:
        syscall: The syscall name this conditional applies to.
        condition_type: One of: capability_gate, argument_filter,
            kernel_version_gate, arch_filter, deny_with_cap_exclude.
        multiplier: The weight multiplier applied (e.g., 0.5).
        details: Human-readable description of the condition.
        rule_action: The original seccomp action (e.g., SCMP_ACT_ALLOW).
    """
    syscall: str
    condition_type: str
    multiplier: float
    details: str
    rule_action: str


# Actions that let a syscall through
_PERMISSIVE = {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}
# Actions that block a syscall
_BLOCKING = {
    "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_KILL",
    "SCMP_ACT_TRAP", "SCMP_ACT_ERRNO",
}


def _rule_has_args(rule: dict) -> bool:
    """Check if a rule has meaningful argument filters."""
    args = rule.get("args")
    if args is None:
        return False
    if isinstance(args, list) and len(args) > 0:
        return True
    return False


def _rule_has_includes(rule: dict) -> dict[str, Any]:
    """Extract non-empty includes from a rule."""
    includes = rule.get("includes", {})
    if not isinstance(includes, dict):
        return {}
    return {k: v for k, v in includes.items() if v}


def _rule_has_excludes(rule: dict) -> dict[str, Any]:
    """Extract non-empty excludes from a rule."""
    excludes = rule.get("excludes", {})
    if not isinstance(excludes, dict):
        return {}
    return {k: v for k, v in excludes.items() if v}


def analyze_conditionals(profile: dict) -> list[ConditionalNote]:
    """Analyze all conditional rules in a profile.

    Scans every syscall rule and produces ConditionalNote entries for
    rules that have conditions (args, includes, excludes).

    Args:
        profile: OCI seccomp profile dict.

    Returns:
        List of ConditionalNote entries describing each conditional found.
    """
    notes: list[ConditionalNote] = []

    for rule in profile.get("syscalls", []):
        action = rule.get("action", "")
        names = rule.get("names", [])
        if not names:
            continue

        has_args = _rule_has_args(rule)
        includes = _rule_has_includes(rule)
        excludes = _rule_has_excludes(rule)

        has_cap_include = bool(includes.get("caps"))
        has_cap_exclude = bool(excludes.get("caps"))
        has_min_kernel = bool(includes.get("minKernel"))
        has_arch_include = bool(includes.get("arches"))
        has_arch_exclude = bool(excludes.get("arches"))

        has_condition = has_args or has_cap_include or has_cap_exclude or has_min_kernel or has_arch_include

        if not has_condition:
            continue

        for name in names:
            if action in _PERMISSIVE:
                if has_cap_include:
                    caps = includes["caps"]
                    notes.append(ConditionalNote(
                        syscall=name,
                        condition_type="capability_gate",
                        multiplier=0.5,
                        details=f"Allowed only with capabilities: {', '.join(caps)}",
                        rule_action=action,
                    ))
                elif has_min_kernel:
                    kernel = includes["minKernel"]
                    notes.append(ConditionalNote(
                        syscall=name,
                        condition_type="kernel_version_gate",
                        multiplier=0.5,
                        details=f"Allowed only on kernel >= {kernel}",
                        rule_action=action,
                    ))
                elif has_args:
                    notes.append(ConditionalNote(
                        syscall=name,
                        condition_type="argument_filter",
                        multiplier=0.5,
                        details=f"Allowed with argument filter ({len(rule.get('args', []))} conditions)",
                        rule_action=action,
                    ))
                elif has_arch_include:
                    arches = includes["arches"]
                    notes.append(ConditionalNote(
                        syscall=name,
                        condition_type="arch_filter",
                        multiplier=0.5,
                        details=f"Allowed only on architectures: {', '.join(arches)}",
                        rule_action=action,
                    ))

                # Handle combined conditions: allow with args AND excludes.caps
                if has_args and has_cap_exclude and not has_cap_include:
                    caps = excludes["caps"]
                    notes.append(ConditionalNote(
                        syscall=name,
                        condition_type="argument_filter",
                        multiplier=0.5,
                        details=f"Arg-filtered allow, excluded when caps: {', '.join(caps)}",
                        rule_action=action,
                    ))

            elif action in _BLOCKING:
                if has_cap_exclude:
                    caps = excludes["caps"]
                    notes.append(ConditionalNote(
                        syscall=name,
                        condition_type="deny_with_cap_exclude",
                        multiplier=0.5,
                        details=f"Blocked unless process has capabilities: {', '.join(caps)}",
                        rule_action=action,
                    ))

    return notes


def resolve_effective_state(
    profile: dict,
    syscall_set: frozenset[str],
) -> dict[str, str]:
    """Compute effective state for each syscall considering conditionals.

    Returns mapping of syscall -> "blocked" | "conditional" | "allowed".

    Resolution rules:
    - Unconditional ALLOW -> "allowed" (1.0x)
    - Conditional ALLOW (caps/args/kernel) -> "conditional" (0.5x)
    - Deny with cap exclude -> "conditional" (0.5x) -- bypass possible
    - Deny with only args -> "blocked" (tightens block)
    - No rule -> falls back to defaultAction
    - Multiple rules: most permissive interpretation wins

    Args:
        profile: OCI seccomp profile dict.
        syscall_set: Set of syscall names to resolve states for.

    Returns:
        Dict mapping syscall name to effective state string.
    """
    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    default_permissive = default_action in _PERMISSIVE

    # Track dispositions per syscall
    unconditional_allow: set[str] = set()
    unconditional_block: set[str] = set()
    conditional_allow: set[str] = set()

    for rule in profile.get("syscalls", []):
        action = rule.get("action", "")
        names = [n for n in rule.get("names", []) if n in syscall_set]
        if not names:
            continue

        has_args = _rule_has_args(rule)
        includes = _rule_has_includes(rule)
        excludes = _rule_has_excludes(rule)
        has_cap_exclude = bool(excludes.get("caps"))

        has_condition = bool(
            has_args or includes.get("caps") or includes.get("minKernel")
            or includes.get("arches") or has_cap_exclude
        )

        if not has_condition:
            if action in _BLOCKING:
                unconditional_block.update(names)
            elif action in _PERMISSIVE:
                unconditional_allow.update(names)
        else:
            if action in _BLOCKING:
                if has_cap_exclude:
                    # Block bypassed when process has the cap -> conditional
                    conditional_allow.update(names)
                # else: arg-filtered deny tightens block -> stays blocked
            elif action in _PERMISSIVE:
                # Allow behind a gate -> conditional
                conditional_allow.update(names)

    states: dict[str, str] = {}
    for sc in syscall_set:
        if sc in unconditional_allow:
            # Most permissive: unconditional allow wins
            states[sc] = "allowed"
        elif sc in conditional_allow and sc not in unconditional_block:
            states[sc] = "conditional"
        elif sc in conditional_allow and sc in unconditional_block:
            # Both conditional allow and unconditional block exist;
            # conditional allow is more permissive
            states[sc] = "conditional"
        elif sc in unconditional_block:
            states[sc] = "blocked"
        else:
            # No explicit rule -> default
            states[sc] = "allowed" if default_permissive else "blocked"

    return states
