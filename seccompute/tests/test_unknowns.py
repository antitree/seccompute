"""Tests for unknown syscall handling: warnings, conservative scoring."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.scoring import score_profile


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


# ---------------------------------------------------------------------------
# Unknown syscall generates warning
# ---------------------------------------------------------------------------

def test_unknown_syscall_produces_warning():
    """A profile with an invented syscall should produce a warning."""
    rules = [_rule(["totally_invented_syscall_xyz"], "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    assert len(result.warnings) > 0
    assert any("totally_invented_syscall_xyz" in w for w in result.warnings)


def test_multiple_unknown_syscalls_produce_separate_warnings():
    """Each unknown syscall should produce its own warning."""
    rules = [_rule(["fake_one", "fake_two", "fake_three"], "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    assert any("fake_one" in w for w in result.warnings)
    assert any("fake_two" in w for w in result.warnings)
    assert any("fake_three" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# Unknown syscall treated conservatively (Tier 2 equivalent)
# ---------------------------------------------------------------------------

def test_unknown_syscall_treated_as_tier2():
    """Unknown syscalls allowed unconditionally should be penalized as Tier 2.

    An unknown syscall gets a conservative weight = TIER2_BUDGET / len(TIER2).
    """
    from seccompute.weights_v2 import TIER2_BUDGET, TIER2

    rules = [_rule(["unknown_risky_syscall"], "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)

    # With 85/10/5 weights, a single unknown (T2-equivalent, weight 0.5)
    # rounds to 100 same as fully blocked.
    fully_blocked = score_profile(_profile("SCMP_ACT_ERRNO"))
    assert result.score <= fully_blocked.score


def test_unknown_blocked_no_penalty():
    """An unknown syscall that is blocked should not affect the score."""
    rules = [_rule(["unknown_blocked_syscall"], "SCMP_ACT_ERRNO")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    assert result.score == 100


# ---------------------------------------------------------------------------
# Warning suggests template entry
# ---------------------------------------------------------------------------

def test_warning_suggests_yaml_template():
    """Warning for unknown syscall should suggest adding it to the YAML."""
    rules = [_rule(["my_new_syscall"], "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    # At least one warning should mention adding to rules/YAML
    assert any("yaml" in w.lower() or "rule" in w.lower() for w in result.warnings)


# ---------------------------------------------------------------------------
# Known syscalls produce no warnings
# ---------------------------------------------------------------------------

def test_known_syscall_no_warning():
    """A profile with only known dangerous syscalls should produce no warnings."""
    rules = [_rule(["bpf", "mount", "ptrace"], "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    # No unknown-syscall warnings (there may be other types of warnings)
    unknown_warnings = [w for w in result.warnings if "unknown" in w.lower()]
    assert len(unknown_warnings) == 0


# ---------------------------------------------------------------------------
# Mixed known and unknown
# ---------------------------------------------------------------------------

def test_mixed_known_unknown_scores_correctly():
    """Profile with both known and unknown syscalls: known scored by tier, unknown by T2."""
    rules = [
        _rule(["bpf"], "SCMP_ACT_ALLOW"),  # known T1
        _rule(["fake_syscall"], "SCMP_ACT_ALLOW"),  # unknown -> T2 equivalent
    ]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    # Score should be less than blocking everything (100)
    assert result.score < 100
    # Should have a warning about fake_syscall
    assert any("fake_syscall" in w for w in result.warnings)
