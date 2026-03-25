"""Conditional analysis for seccomp profile rules.

Detects and classifies conditionals in seccomp rules and resolves
effective syscall states considering conditional allows/denies.
"""
from __future__ import annotations

from .model import ConditionalFinding

# Actions that let a syscall through
_PERMISSIVE = {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}
# Actions that block a syscall
_BLOCKING = {
    "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_KILL",
    "SCMP_ACT_TRAP", "SCMP_ACT_ERRNO",
}


def _has_args(rule: dict) -> bool:
    args = rule.get("args")
    return isinstance(args, list) and len(args) > 0


def _get_includes(rule: dict) -> dict:
    inc = rule.get("includes", {})
    return inc if isinstance(inc, dict) else {}


def _get_excludes(rule: dict) -> dict:
    exc = rule.get("excludes", {})
    return exc if isinstance(exc, dict) else {}


def analyze_conditionals(profile: dict, *, granted_caps: frozenset[str] | None = None) -> list[ConditionalFinding]:
    """Analyze all conditional rules in a profile.

    Returns ConditionalFinding entries for rules with conditions.
    """
    findings: list[ConditionalFinding] = []

    for rule in profile.get("syscalls", []):
        action = rule.get("action", "")
        names = rule.get("names", [])
        if not names:
            continue

        has_args = _has_args(rule)
        includes = _get_includes(rule)
        excludes = _get_excludes(rule)
        has_cap_include = bool(includes.get("caps"))
        has_cap_exclude = bool(excludes.get("caps"))
        has_min_kernel = bool(includes.get("minKernel"))
        has_arch_include = bool(includes.get("arches"))

        has_condition = has_args or has_cap_include or has_cap_exclude or has_min_kernel or has_arch_include
        if not has_condition:
            continue

        for name in names:
            if action in _PERMISSIVE:
                if has_cap_include:
                    caps = includes["caps"]
                    if granted_caps is None:
                        resolved = None
                    else:
                        resolved = all(c in granted_caps for c in caps)
                    findings.append(ConditionalFinding(
                        syscall=name,
                        condition_type="capability_gate",
                        details=f"Allowed only with capabilities: {', '.join(caps)}",
                        rule_action=action,
                        resolved=resolved,
                    ))
                elif has_min_kernel:
                    kernel = includes["minKernel"]
                    findings.append(ConditionalFinding(
                        syscall=name,
                        condition_type="kernel_version_gate",
                        details=f"Allowed only on kernel >= {kernel}",
                        rule_action=action,
                    ))
                elif has_args:
                    findings.append(ConditionalFinding(
                        syscall=name,
                        condition_type="argument_filter",
                        details=f"Allowed with argument filter ({len(rule.get('args', []))} conditions)",
                        rule_action=action,
                    ))
                elif has_arch_include:
                    arches = includes["arches"]
                    findings.append(ConditionalFinding(
                        syscall=name,
                        condition_type="arch_filter",
                        details=f"Allowed only on architectures: {', '.join(arches)}",
                        rule_action=action,
                    ))
            elif action in _BLOCKING:
                if has_cap_exclude:
                    caps = excludes["caps"]
                    findings.append(ConditionalFinding(
                        syscall=name,
                        condition_type="deny_with_cap_exclude",
                        details=f"Blocked unless process has capabilities: {', '.join(caps)}",
                        rule_action=action,
                    ))

    return findings


def resolve_effective_states(
    profile: dict,
    syscall_set: frozenset[str],
    granted_caps: frozenset[str] | None = None,
) -> dict[str, str]:
    """Compute effective state for each syscall in syscall_set.

    Returns mapping of syscall -> "blocked" | "conditional" | "allowed".

    Resolution: most permissive interpretation wins when multiple rules
    mention the same syscall.
    """
    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    default_permissive = default_action in _PERMISSIVE

    unconditional_allow: set[str] = set()
    unconditional_block: set[str] = set()
    conditional_allow: set[str] = set()

    for rule in profile.get("syscalls", []):
        action = rule.get("action", "")
        names = [n for n in rule.get("names", []) if n in syscall_set]
        if not names:
            continue

        has_args = _has_args(rule)
        includes = _get_includes(rule)
        excludes = _get_excludes(rule)
        has_cap_exclude = bool(excludes.get("caps"))

        has_condition = bool(
            has_args or includes.get("caps") or includes.get("minKernel")
            or includes.get("arches") or has_cap_exclude
        )

        has_cap_include = bool(includes.get("caps"))

        if not has_condition:
            if action in _BLOCKING:
                unconditional_block.update(names)
            elif action in _PERMISSIVE:
                unconditional_allow.update(names)
        else:
            if action in _BLOCKING:
                if has_cap_exclude:
                    conditional_allow.update(names)
                # else: arg-filtered deny tightens block
            elif action in _PERMISSIVE:
                if has_cap_include:
                    # Cap-gated allow: resolution depends on granted_caps context
                    if granted_caps is None:
                        # No caps context — ignore this rule entirely (fall through to default)
                        pass
                    elif frozenset(includes["caps"]).issubset(granted_caps):
                        # All required caps are granted — treat as unconditional allow
                        unconditional_allow.update(names)
                    else:
                        # Required cap(s) not granted — treat as unconditional block
                        unconditional_block.update(names)
                else:
                    conditional_allow.update(names)

    states: dict[str, str] = {}
    for sc in syscall_set:
        if sc in unconditional_allow:
            states[sc] = "allowed"
        elif sc in unconditional_block:
            states[sc] = "blocked"
        elif sc in conditional_allow:
            states[sc] = "conditional"
        else:
            states[sc] = "allowed" if default_permissive else "blocked"

    return states
