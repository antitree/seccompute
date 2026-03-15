"""Core scoring engine for seccomp profiles.

Computes an absolute hardening score (0-100) where:
  0 = maximally permissive (all dangerous syscalls allowed)
  100 = maximally hardened (all dangerous syscalls blocked)

Score = 100 - sum(allowed_syscall_weights), where:
  - Unconditionally allowed syscalls: 1.0x weight penalty
  - Conditionally allowed syscalls: 0.5x weight penalty
  - Blocked syscalls: 0.0x weight penalty

Per-syscall weight = tier_budget / count(syscalls_in_tier):
  - Tier 1 (budget 60): catastrophic (kernel code exec, container escape)
  - Tier 2 (budget 30): serious (namespace/filesystem escape)
  - Tier 3 (budget 10): elevated (contextual risk, DoS)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .conditionals import ConditionalNote, analyze_conditionals, resolve_effective_state
from .known_syscalls import KNOWN_LINUX_SYSCALLS
from .rules import get_all_rules, get_tier
from .weights_v2 import (
    ALL_DANGEROUS_V2,
    TIER1, TIER1_BUDGET,
    TIER2, TIER2_BUDGET,
    TIER3, TIER3_BUDGET,
    tier_weight,
)

ENGINE_VERSION = "2.0.0"

# State multipliers for absolute scoring
_STATE_MULTIPLIER: dict[str, float] = {
    "blocked": 0.0,
    "conditional": 0.5,
    "allowed": 1.0,
}


@dataclass
class TierScore:
    """Per-tier scoring breakdown.

    Attributes:
        tier: Tier number (1, 2, or 3).
        budget: Total points allocated to this tier.
        total_syscalls: Number of syscalls in this tier.
        allowed_count: Number unconditionally allowed.
        conditional_count: Number conditionally allowed.
        blocked_count: Number blocked.
        deduction: Points deducted from this tier.
    """
    tier: int
    budget: float
    total_syscalls: int
    allowed_count: int = 0
    conditional_count: int = 0
    blocked_count: int = 0
    deduction: float = 0.0


@dataclass
class SyscallScore:
    """Per-syscall scoring detail.

    Attributes:
        name: Syscall name.
        tier: Tier assignment (1-3, or 0 for unknown).
        state: Effective state (blocked/conditional/allowed).
        weight: Base weight for this syscall.
        multiplier: State multiplier applied (0.0/0.5/1.0).
        deduction: Actual points deducted (weight * multiplier).
        is_unknown: True if not in syscall_rules.yaml.
    """
    name: str
    tier: int
    state: str
    weight: float
    multiplier: float
    deduction: float
    is_unknown: bool = False


@dataclass
class ScoringResult:
    """Complete scoring result for a seccomp profile.

    Attributes:
        score: Hardening score 0-100 (100 = maximally hardened).
        tier_breakdown: Per-tier scoring statistics.
        syscall_details: Per-syscall scoring details for dangerous syscalls.
        conditionals: Conditional interpretations applied during scoring.
        warnings: Unknown syscalls, inconsistencies, or other issues.
        metadata: Arch, engine version, and other context.
    """
    score: int
    tier_breakdown: dict[str, TierScore]
    syscall_details: list[SyscallScore]
    conditionals: list[ConditionalNote]
    warnings: list[str]
    metadata: dict[str, Any]


def _collect_all_profile_syscalls(profile: dict) -> set[str]:
    """Collect all syscall names mentioned in a profile's rules."""
    names: set[str] = set()
    for rule in profile.get("syscalls", []):
        names.update(rule.get("names", []))
    return names


def _compute_unknown_weight() -> float:
    """Compute the conservative weight for unknown syscalls (Tier 2 equivalent)."""
    return TIER2_BUDGET / len(TIER2)


def score_profile(
    profile: dict,
    arch: str = "SCMP_ARCH_X86_64",
) -> ScoringResult:
    """Score a seccomp profile on a 0-100 hardening scale.

    Args:
        profile: OCI seccomp profile as a dict.
        arch: Target architecture (default: SCMP_ARCH_X86_64).

    Returns:
        ScoringResult with score, breakdown, and details.
    """
    warnings: list[str] = []
    all_rules = get_all_rules()

    # Identify all syscalls in the profile
    profile_syscalls = _collect_all_profile_syscalls(profile)

    # Detect unknown syscalls: only flag names that are not recognized as
    # real Linux syscalls.  Common syscalls like "read", "write", etc. are
    # in KNOWN_LINUX_SYSCALLS and must NOT be treated as unknown.
    unknown_syscalls: set[str] = set()
    for sc in profile_syscalls:
        if (sc not in all_rules
                and sc not in ALL_DANGEROUS_V2
                and sc not in KNOWN_LINUX_SYSCALLS):
            unknown_syscalls.add(sc)

    # Only generate warnings for unknown syscalls that are referenced in
    # allow rules (blocked unknowns are harmless)
    unknown_weight = _compute_unknown_weight()
    active_unknowns: set[str] = set()

    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    permissive_default = default_action in {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}

    # Build the set of syscalls to score: all dangerous + unknowns in profile
    score_set = set(ALL_DANGEROUS_V2)

    # Check which unknowns are effectively allowed
    for sc in unknown_syscalls:
        # Determine if this unknown is allowed
        explicitly_allowed = False
        explicitly_blocked = False
        for rule in profile.get("syscalls", []):
            if sc in rule.get("names", []):
                action = rule.get("action", "")
                if action in {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}:
                    explicitly_allowed = True
                elif action in {"SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS",
                                "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP"}:
                    explicitly_blocked = True

        if explicitly_allowed or (permissive_default and not explicitly_blocked):
            active_unknowns.add(sc)
            score_set.add(sc)
            warnings.append(
                f"Unknown syscall '{sc}' not in syscall_rules.yaml. "
                f"Scored conservatively as Tier 2 (weight={unknown_weight:.2f}). "
                f"Consider adding a rule entry to the YAML."
            )
        elif not explicitly_blocked and not permissive_default:
            # Blocked by default, but still warn about unknown
            warnings.append(
                f"Unknown syscall '{sc}' not in syscall_rules.yaml. "
                f"Currently blocked by defaultAction. "
                f"Consider adding a rule entry to the YAML."
            )

    # Resolve effective states for all scored syscalls
    states = resolve_effective_state(profile, frozenset(score_set))

    # Analyze conditionals
    conditionals = analyze_conditionals(profile)

    # Build tier breakdown
    tier_scores = {
        "tier1": TierScore(tier=1, budget=TIER1_BUDGET, total_syscalls=len(TIER1)),
        "tier2": TierScore(tier=2, budget=TIER2_BUDGET, total_syscalls=len(TIER2)),
        "tier3": TierScore(tier=3, budget=TIER3_BUDGET, total_syscalls=len(TIER3)),
    }

    syscall_details: list[SyscallScore] = []
    total_deduction = 0.0

    # Score known dangerous syscalls
    for sc in sorted(ALL_DANGEROUS_V2):
        state = states.get(sc, "blocked")
        multiplier = _STATE_MULTIPLIER[state]
        weight = tier_weight(sc)
        deduction = weight * multiplier

        total_deduction += deduction

        # Update tier breakdown
        t = get_tier(sc)
        tier_key = f"tier{t}"
        if tier_key in tier_scores:
            tier_scores[tier_key].deduction += deduction
            if state == "allowed":
                tier_scores[tier_key].allowed_count += 1
            elif state == "conditional":
                tier_scores[tier_key].conditional_count += 1
            else:
                tier_scores[tier_key].blocked_count += 1

        syscall_details.append(SyscallScore(
            name=sc,
            tier=t,
            state=state,
            weight=weight,
            multiplier=multiplier,
            deduction=deduction,
        ))

    # Score unknown syscalls that are active
    for sc in sorted(active_unknowns):
        state = states.get(sc, "blocked")
        multiplier = _STATE_MULTIPLIER[state]
        deduction = unknown_weight * multiplier

        total_deduction += deduction

        syscall_details.append(SyscallScore(
            name=sc,
            tier=0,
            state=state,
            weight=unknown_weight,
            multiplier=multiplier,
            deduction=deduction,
            is_unknown=True,
        ))

    # Compute final score
    raw_score = 100.0 - total_deduction
    score = max(0, min(100, round(raw_score)))

    metadata = {
        "arch": arch,
        "engine_version": ENGINE_VERSION,
        "default_action": default_action,
        "total_dangerous_syscalls": len(ALL_DANGEROUS_V2),
        "unknown_syscalls_found": len(active_unknowns),
    }

    return ScoringResult(
        score=score,
        tier_breakdown=tier_scores,
        syscall_details=syscall_details,
        conditionals=conditionals,
        warnings=warnings,
        metadata=metadata,
    )
