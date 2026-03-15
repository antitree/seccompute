"""Tests for scoring.py: absolute scoring math, ScoringResult shape."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.scoring import ScoringResult, score_profile
from seccompute.weights_v2 import (
    ALL_DANGEROUS_V2,
    TIER1, TIER1_BUDGET,
    TIER2, TIER2_BUDGET,
    TIER3, TIER3_BUDGET,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _profile(default_action="SCMP_ACT_ERRNO", rules=None):
    return {"defaultAction": default_action, "syscalls": rules or []}


def _rule(names, action, args=None, includes=None, excludes=None):
    r = {"names": names, "action": action}
    if args:
        r["args"] = args
    if includes:
        r["includes"] = includes
    if excludes:
        r["excludes"] = excludes
    return r


_PROFILES_DIR = Path(__file__).parent.parent.parent / "app" / "static" / "profiles"


# ---------------------------------------------------------------------------
# Empty profile edge cases
# ---------------------------------------------------------------------------

def test_empty_allow_default_scores_zero():
    """defaultAction=ALLOW with no rules: everything allowed, score = 0."""
    p = _profile("SCMP_ACT_ALLOW")
    result = score_profile(p)
    assert result.score == 0


def test_empty_errno_default_scores_100():
    """defaultAction=ERRNO with no rules: everything blocked, score = 100."""
    p = _profile("SCMP_ACT_ERRNO")
    result = score_profile(p)
    assert result.score == 100


# ---------------------------------------------------------------------------
# Docker default profile scoring
# ---------------------------------------------------------------------------

def test_docker_default_profile_score():
    """Load the real Docker default profile and verify score is reasonable.

    Docker default: ERRNO base, allows ~360 syscalls unconditionally,
    plus capability-gated allows for dangerous syscalls.
    Most dangerous syscalls are conditionally allowed (cap-gated).
    Expected: high score (70-95) because base is deny-all and dangerous
    syscalls require capabilities.
    """
    docker_path = _PROFILES_DIR / "DEFAULT-docker.json"
    if not docker_path.exists():
        pytest.skip("Docker default profile not found")

    with open(docker_path) as f:
        profile = json.load(f)

    result = score_profile(profile)
    # Docker default should score between 50 and 95 (deny-all base with cap-gated
    # dangerous syscalls -- conditionals reduce score from 100 but not to 0)
    assert 50 <= result.score <= 95, f"Docker default score {result.score} out of expected range"
    assert isinstance(result, ScoringResult)


# ---------------------------------------------------------------------------
# Tier-specific scoring
# ---------------------------------------------------------------------------

def test_all_tier1_allowed_loses_60_points():
    """Allowing all T1 syscalls unconditionally costs exactly 60 points."""
    rules = [_rule(list(TIER1), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    # Score = 100 - 60 (T1 budget fully deducted) = 40
    assert result.score == 40


def test_all_tier2_allowed_loses_30_points():
    """Allowing all T2 syscalls unconditionally costs exactly 30 points."""
    rules = [_rule(list(TIER2), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    # Score = 100 - 30 (T2 budget fully deducted) = 70
    assert result.score == 70


def test_all_tier3_allowed_loses_10_points():
    """Allowing all T3 syscalls unconditionally costs exactly 10 points."""
    rules = [_rule(list(TIER3), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    # Score = 100 - 10 (T3 budget fully deducted) = 90
    assert result.score == 90


def test_all_dangerous_allowed_scores_zero():
    """Allowing all dangerous syscalls should score 0."""
    rules = [_rule(list(ALL_DANGEROUS_V2), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    assert result.score == 0


def test_single_tier1_allowed():
    """Allowing one T1 syscall deducts tier1_budget / len(tier1)."""
    rules = [_rule(["bpf"], "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    expected_deduction = TIER1_BUDGET / len(TIER1)
    expected_score = round(100 - expected_deduction)
    assert result.score == expected_score


# ---------------------------------------------------------------------------
# ScoringResult shape
# ---------------------------------------------------------------------------

def test_scoring_result_fields():
    """ScoringResult must have all required fields."""
    p = _profile("SCMP_ACT_ERRNO")
    result = score_profile(p)
    assert hasattr(result, "score")
    assert hasattr(result, "tier_breakdown")
    assert hasattr(result, "syscall_details")
    assert hasattr(result, "conditionals")
    assert hasattr(result, "warnings")
    assert hasattr(result, "metadata")


def test_scoring_result_tier_breakdown():
    """tier_breakdown must have entries for each tier."""
    p = _profile("SCMP_ACT_ERRNO")
    result = score_profile(p)
    assert "tier1" in result.tier_breakdown
    assert "tier2" in result.tier_breakdown
    assert "tier3" in result.tier_breakdown


def test_scoring_result_metadata():
    """metadata must contain arch and engine_version."""
    p = _profile("SCMP_ACT_ERRNO")
    result = score_profile(p)
    assert "arch" in result.metadata
    assert "engine_version" in result.metadata


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_scoring_deterministic():
    """Same input must always produce same score."""
    rules = [_rule(["bpf", "mount"], "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    results = [score_profile(p) for _ in range(5)]
    for r in results[1:]:
        assert r.score == results[0].score


# ---------------------------------------------------------------------------
# Conditional scoring (0.5x weight)
# ---------------------------------------------------------------------------

def test_conditional_allow_half_weight():
    """A capability-gated allow should deduct only 0.5x the syscall weight."""
    # bpf allowed only with CAP_BPF -> conditional -> 0.5x penalty
    rules = [_rule(["bpf"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_BPF"]})]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)

    full_deduction = TIER1_BUDGET / len(TIER1)
    half_deduction = full_deduction * 0.5
    expected_score = round(100 - half_deduction)
    assert result.score == expected_score


def test_conditional_scores_between_blocked_and_allowed():
    """A conditional allow should score between fully blocked and fully allowed."""
    # Fully blocked
    p_blocked = _profile("SCMP_ACT_ERRNO")
    r_blocked = score_profile(p_blocked)

    # Fully allowed
    rules_allowed = [_rule(["bpf"], "SCMP_ACT_ALLOW")]
    p_allowed = _profile("SCMP_ACT_ERRNO", rules_allowed)
    r_allowed = score_profile(p_allowed)

    # Conditional
    rules_cond = [_rule(["bpf"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_BPF"]})]
    p_cond = _profile("SCMP_ACT_ERRNO", rules_cond)
    r_cond = score_profile(p_cond)

    assert r_allowed.score < r_cond.score < r_blocked.score


# ---------------------------------------------------------------------------
# Score clamping
# ---------------------------------------------------------------------------

def test_score_clamped_to_0_100():
    """Score must always be in [0, 100]."""
    for default in ["SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO"]:
        result = score_profile(_profile(default))
        assert 0 <= result.score <= 100
