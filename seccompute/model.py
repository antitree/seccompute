"""Syscall state resolution and scoring for seccompute.

Analysis model (per spec):
  - Effective state per syscall:
      Precedence: explicit rule > defaultAction
      Conditional allow (args/includes/excludes) → state "conditional"
      Deny with excludes.caps → "conditional" (bypass possible with caps)
      Deny with only arg filters → "blocked" (tightens block)
      No explicit rule → falls back to defaultAction
        ALLOW/LOG/TRACE → "allowed"; ERRNO/TRAP/KILL* → "blocked"
  - State scores: blocked=0.0, conditional=0.5, allowed=1.0
  - Risk = weighted sum over DANGEROUS_SYSCALLS
"""

from __future__ import annotations

import hashlib
from typing import Any

from .weights import DANGEROUS_SYSCALLS, HIGH_RISK_WEIGHTS
from .weights_v2 import ALL_DANGEROUS_V2, TOTAL_KNOWN_SYSCALLS, tier_weight

# Actions that let a syscall through
_PERMISSIVE = {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}
# Actions that block a syscall
_BLOCKING = {
    "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_KILL",
    "SCMP_ACT_TRAP", "SCMP_ACT_ERRNO",
}

_STATE_SCORE: dict[str, float] = {
    "blocked": 0.0,
    "conditional": 0.5,
    "allowed": 1.0,
}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def is_valid(data: Any) -> tuple[bool, str | None]:
    """Return (valid, reason_if_invalid)."""
    if not isinstance(data, dict):
        return False, "not_a_json_object"
    if "defaultAction" not in data:
        return False, "missing_defaultAction"
    if not isinstance(data.get("syscalls"), list):
        return False, "missing_syscalls_array"
    return True, None


def _syscall_states(profile: dict, syscall_set: frozenset[str]) -> dict[str, str]:
    """Compute effective state for each syscall in syscall_set.

    Returns mapping syscall -> "blocked" | "conditional" | "allowed".
    Uses single-pass rule accumulation then resolves per-syscall.
    """
    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    default_permissive = default_action in _PERMISSIVE

    # Accumulate dispositions from rules (a syscall can appear in multiple rules)
    unconditional_block: set[str] = set()
    unconditional_allow: set[str] = set()
    conditional_allow: set[str] = set()   # reachable behind a gate

    for rule in profile.get("syscalls", []):
        action = rule.get("action", "")
        names = [n for n in rule.get("names", []) if n in syscall_set]
        if not names:
            continue

        args = rule.get("args", [])
        includes = rule.get("includes", {})
        excludes = rule.get("excludes", {})
        if not isinstance(includes, dict):
            includes = {}
        if not isinstance(excludes, dict):
            excludes = {}
        has_condition = bool(args or includes or excludes)
        has_cap_exclude = bool(excludes.get("caps"))

        if not has_condition:
            if action in _BLOCKING:
                unconditional_block.update(names)
            elif action in _PERMISSIVE:
                unconditional_allow.update(names)
        else:
            if action in _BLOCKING:
                if has_cap_exclude:
                    # Block lifted when process holds the cap → conditional reachability
                    conditional_allow.update(names)
                # else: arg-filtered deny → tightens block, treat as blocked (don't add to allow sets)
            elif action in _PERMISSIVE:
                # Allow behind a gate
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
            # No explicit rule → defaultAction
            states[sc] = "allowed" if default_permissive else "blocked"
    return states


def _risk(states: dict[str, str], weights: dict[str, float] | None = None) -> float:
    total = 0.0
    for sc, state in states.items():
        w = float((weights or {}).get(sc, 1.0))
        total += w * _STATE_SCORE.get(state, 0.0)
    return total


def _condition_usage(profile: dict) -> dict[str, int]:
    """Count condition types across all syscall rules."""
    counts: dict[str, int] = {
        "capInclude": 0,
        "capExclude": 0,
        "argFilter": 0,
        "archInclude": 0,
        "minKernel": 0,
    }
    for rule in profile.get("syscalls", []):
        args = rule.get("args", [])
        includes = rule.get("includes", {})
        excludes = rule.get("excludes", {})
        if not isinstance(includes, dict):
            includes = {}
        if not isinstance(excludes, dict):
            excludes = {}
        if args:
            counts["argFilter"] += len(args)
        if includes.get("caps"):
            counts["capInclude"] += len(includes["caps"])
        if includes.get("arches"):
            counts["archInclude"] += 1
        if includes.get("minKernel"):
            counts["minKernel"] += 1
        if excludes.get("caps"):
            counts["capExclude"] += len(excludes["caps"])
    return counts


def score_attack_surface(profile: dict) -> float:
    """Compute Attack Surface Score (0-100). Higher = fewer syscalls allowed.

    Measures how much of the total known syscall universe the profile blocks.
    """
    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    default_permissive = default_action in _PERMISSIVE

    if not default_permissive:
        # DENY-by-default: count syscalls with explicit ALLOW/LOG/TRACE rules
        allowed_names: set[str] = set()
        for rule in profile.get("syscalls", []):
            if rule.get("action", "") in _PERMISSIVE:
                allowed_names.update(rule.get("names", []))
        allowed_count = len(allowed_names)
    else:
        # ALLOW-by-default: count syscalls with explicit DENY rules
        denied_names: set[str] = set()
        for rule in profile.get("syscalls", []):
            if rule.get("action", "") in _BLOCKING:
                denied_names.update(rule.get("names", []))
        allowed_count = TOTAL_KNOWN_SYSCALLS - len(denied_names)

    score = round((1 - allowed_count / TOTAL_KNOWN_SYSCALLS) * 100, 1)
    return float(max(0.0, min(100.0, score)))


# State multipliers for dangerous exposure scoring
_DE_STATE_MULT: dict[str, float] = {
    "blocked": 0.0,
    "conditional": 0.1,
    "allowed": 1.0,
}


def score_dangerous_exposure(profile: dict) -> float:
    """Compute Dangerous Exposure Score (-100 to 0). 0 = no dangerous syscalls allowed.

    Penalty-only model. Only dangerous syscalls contribute.
    Uses tiered weights from weights_v2.
    """
    states = _syscall_states(profile, ALL_DANGEROUS_V2)
    raw = sum(tier_weight(sc) * _DE_STATE_MULT[states[sc]] for sc in ALL_DANGEROUS_V2)
    score = -round(raw, 1)
    return float(max(-100.0, min(0.0, score)))


def score_profile(
    profile: dict,
    ref_states: dict[str, str],
    ref_risk: float,
) -> dict:
    """Compute all per-profile metrics against a pre-computed reference.

    Returns a dict matching the spec's profiles[] fields (minus filename/sha256/valid/skippedReason).
    """
    dangerous = frozenset(DANGEROUS_SYSCALLS)
    prof_states = _syscall_states(profile, dangerous)
    profile_risk = _risk(prof_states, HIGH_RISK_WEIGHTS)

    # vs-default delta
    if ref_risk > 0:
        delta_pct = round((ref_risk - profile_risk) * 100.0 / ref_risk, 1)
    else:
        delta_pct = round(-profile_risk * 100.0, 1) if profile_risk > 0 else 0.0

    # improved / regressed syscalls
    order = {"blocked": 0, "conditional": 1, "allowed": 2}
    improved: list[str] = []
    regressed: list[str] = []
    for sc in dangerous:
        prof_ord = order[prof_states[sc]]
        ref_ord = order[ref_states[sc]]
        if prof_ord < ref_ord:
            improved.append(sc)
        elif prof_ord > ref_ord:
            regressed.append(sc)

    # vs-none coverage
    blocked = [sc for sc in dangerous if prof_states[sc] == "blocked"]
    allowed_uncond = sorted(sc for sc in dangerous if prof_states[sc] == "allowed")
    allowed_cond = sorted(sc for sc in dangerous if prof_states[sc] == "conditional")
    total_dangerous = len(dangerous)
    vs_none_pct = round(len(blocked) * 100.0 / total_dangerous, 1) if total_dangerous else 0.0

    return {
        "vsDefaultHardeningDeltaPct": delta_pct,
        "defaultRisk": round(ref_risk, 2),
        "profileRisk": round(profile_risk, 2),
        "vsNoneCoveragePct": vs_none_pct,
        "dangerousBlockedCount": len(blocked),
        "dangerousAllowedUnconditionally": allowed_uncond,
        "dangerousAllowedConditionally": allowed_cond,
        "improvedSyscalls": sorted(improved),
        "regressedSyscalls": sorted(regressed),
        "attackSurfaceScore": score_attack_surface(profile),
        "dangerousExposureScore": score_dangerous_exposure(profile),
    }


def reference_states_and_risk(ref_profile: dict) -> tuple[dict[str, str], float]:
    """Compute memoizable reference states and risk score."""
    states = _syscall_states(ref_profile, frozenset(DANGEROUS_SYSCALLS))
    risk = _risk(states, HIGH_RISK_WEIGHTS)
    return states, risk


def dangerous_reachability_entry(prof_states: dict[str, str]) -> dict[str, str]:
    """Return per-dangerous-syscall state string for aggregation."""
    return {sc: prof_states.get(sc, "blocked") for sc in sorted(DANGEROUS_SYSCALLS)}
