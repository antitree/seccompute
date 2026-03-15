"""Tests for model.py: rule precedence, condition handling, defaultAction fallback,
weighted delta correctness, and output determinism.
"""

import pytest
import sys
from pathlib import Path

# Allow running from repo root: python -m pytest seccompute/tests/
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.model import (
    _risk,
    _syscall_states,
    is_valid,
    reference_states_and_risk,
    score_attack_surface,
    score_dangerous_exposure,
    score_profile,
    sha256_file,
)
from seccompute.weights import DANGEROUS_SYSCALLS, HIGH_RISK_WEIGHTS
from seccompute.weights_v2 import (
    ALL_DANGEROUS_V2,
    TIER1, TIER1_BUDGET,
    TIER2, TIER2_BUDGET,
    TIER3, TIER3_BUDGET,
    TOTAL_KNOWN_SYSCALLS,
    tier_weight,
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


_dangerous_set = frozenset(DANGEROUS_SYSCALLS)

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_valid_profile_accepted():
    ok, reason = is_valid(_profile())
    assert ok
    assert reason is None


def test_missing_default_action_rejected():
    ok, reason = is_valid({"syscalls": []})
    assert not ok
    assert "defaultAction" in reason


def test_missing_syscalls_array_rejected():
    ok, reason = is_valid({"defaultAction": "SCMP_ACT_ERRNO"})
    assert not ok


def test_non_dict_rejected():
    ok, reason = is_valid([])
    assert not ok
    assert reason == "not_a_json_object"


# ---------------------------------------------------------------------------
# Rule precedence: explicit rule > defaultAction
# ---------------------------------------------------------------------------

def test_explicit_allow_overrides_blocking_default():
    """Unconditional ALLOW rule must override a blocking defaultAction."""
    p = _profile("SCMP_ACT_ERRNO", [_rule(["ptrace"], "SCMP_ACT_ALLOW")])
    states = _syscall_states(p, _dangerous_set)
    assert states["ptrace"] == "allowed"


def test_explicit_block_overrides_permissive_default():
    """Unconditional ERRNO rule must override a permissive defaultAction."""
    p = _profile("SCMP_ACT_ALLOW", [_rule(["ptrace"], "SCMP_ACT_ERRNO")])
    states = _syscall_states(p, _dangerous_set)
    assert states["ptrace"] == "blocked"


# ---------------------------------------------------------------------------
# defaultAction fallback
# ---------------------------------------------------------------------------

def test_permissive_default_no_rule_gives_allowed():
    p = _profile("SCMP_ACT_ALLOW")
    states = _syscall_states(p, _dangerous_set)
    # All dangerous syscalls with no explicit rule should be "allowed"
    for sc in DANGEROUS_SYSCALLS:
        assert states[sc] == "allowed", f"{sc} should be allowed via permissive default"


def test_blocking_default_no_rule_gives_blocked():
    p = _profile("SCMP_ACT_ERRNO")
    states = _syscall_states(p, _dangerous_set)
    for sc in DANGEROUS_SYSCALLS:
        assert states[sc] == "blocked", f"{sc} should be blocked via blocking default"


def test_scmp_act_log_is_permissive():
    p = _profile("SCMP_ACT_LOG")
    states = _syscall_states(p, _dangerous_set)
    assert states["bpf"] == "allowed"


def test_scmp_act_kill_is_blocking():
    p = _profile("SCMP_ACT_KILL")
    states = _syscall_states(p, _dangerous_set)
    assert states["bpf"] == "blocked"


# ---------------------------------------------------------------------------
# Conditional allow handling
# ---------------------------------------------------------------------------

def test_arg_filtered_allow_is_conditional():
    """An ALLOW rule with args → state is 'conditional'."""
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["bpf"], "SCMP_ACT_ALLOW", args=[{"index": 0, "op": "SCMP_CMP_EQ", "value": 0}])
    ])
    states = _syscall_states(p, _dangerous_set)
    assert states["bpf"] == "conditional"


def test_cap_include_allow_is_conditional():
    """An ALLOW rule with includes.caps → state is 'conditional'."""
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["mount"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_SYS_ADMIN"]})
    ])
    states = _syscall_states(p, _dangerous_set)
    assert states["mount"] == "conditional"


# ---------------------------------------------------------------------------
# Deny with excludes.caps → conditional (spec: bypass possible with caps)
# ---------------------------------------------------------------------------

def test_deny_with_cap_exclude_is_conditional():
    """ERRNO + excludes.caps means 'block UNLESS you have the cap' → conditional."""
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["chroot"], "SCMP_ACT_ERRNO", excludes={"caps": ["CAP_SYS_CHROOT"]})
    ])
    states = _syscall_states(p, _dangerous_set)
    assert states["chroot"] == "conditional"


# ---------------------------------------------------------------------------
# Deny with only arg filters → blocked (tightens block, not weakened)
# ---------------------------------------------------------------------------

def test_deny_with_only_arg_filter_is_blocked():
    """ERRNO + args only (no cap exclude) → blocked, not conditional.

    A blocking rule with only arg filters tightens the block (spec: "remains blocked").
    The syscall is NOT promoted to conditional — it stays blocked regardless of
    the defaultAction because the unconditional block set captures it.
    Base case: blocking defaultAction so there is no unconditional allow to compete.
    """
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["clone"], "SCMP_ACT_ERRNO", args=[{"index": 0, "op": "SCMP_CMP_MASKED_EQ", "value": 256}])
    ])
    states = _syscall_states(p, _dangerous_set)
    # Arg-filtered ERRNO with blocking default → clone is blocked (not conditional)
    assert states["clone"] == "blocked"


# ---------------------------------------------------------------------------
# Weighted delta correctness
# ---------------------------------------------------------------------------

def test_fully_blocked_profile_has_zero_risk():
    """A profile blocking every dangerous syscall should score 0 risk."""
    rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ERRNO")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    states = _syscall_states(p, _dangerous_set)
    assert _risk(states, HIGH_RISK_WEIGHTS) == 0.0


def test_fully_open_profile_has_max_risk():
    """A profile allowing every dangerous syscall should score maximum risk."""
    rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    states = _syscall_states(p, _dangerous_set)
    r = _risk(states, HIGH_RISK_WEIGHTS)
    # Max risk = sum of all weights (state score 1.0 each)
    max_risk = sum(HIGH_RISK_WEIGHTS.get(sc, 1.0) for sc in DANGEROUS_SYSCALLS)
    assert r == pytest.approx(max_risk)


def test_high_risk_syscall_materially_influences_delta():
    """Blocking bpf (weight=3) should produce a larger delta than blocking acct (weight=2).

    Reference: all dangerous syscalls allowed via permissive defaultAction (no rules).
    Profile A: blocks only bpf (weight=3) via explicit ERRNO rule.
    Profile B: blocks only acct (weight=2) via explicit ERRNO rule.
    Both profiles allow everything else via permissive defaultAction.
    """
    # Reference: permissive default, no rules → all dangerous syscalls "allowed"
    ref = _profile("SCMP_ACT_ALLOW")
    ref_states, ref_risk = reference_states_and_risk(ref)

    # Profile A: permissive default + explicit block on bpf only
    p_a = _profile("SCMP_ACT_ALLOW", [_rule(["bpf"], "SCMP_ACT_ERRNO")])

    # Profile B: permissive default + explicit block on acct only
    p_b = _profile("SCMP_ACT_ALLOW", [_rule(["acct"], "SCMP_ACT_ERRNO")])

    metrics_a = score_profile(p_a, ref_states, ref_risk)
    metrics_b = score_profile(p_b, ref_states, ref_risk)

    assert metrics_a["vsDefaultHardeningDeltaPct"] > metrics_b["vsDefaultHardeningDeltaPct"]


def test_delta_pct_positive_when_more_hardened():
    ref_rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    ref = _profile("SCMP_ACT_ERRNO", ref_rules)
    ref_states, ref_risk = reference_states_and_risk(ref)

    # Profile blocks everything
    p = _profile("SCMP_ACT_ERRNO")
    metrics = score_profile(p, ref_states, ref_risk)
    assert metrics["vsDefaultHardeningDeltaPct"] == 100.0


def test_delta_pct_negative_when_less_hardened():
    # Reference already blocks everything
    ref = _profile("SCMP_ACT_ERRNO")
    ref_states, ref_risk = reference_states_and_risk(ref)

    # Profile allows everything
    p_rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", p_rules)
    metrics = score_profile(p, ref_states, ref_risk)
    # ref_risk is 0 and profile_risk > 0 → spec: -100%
    assert metrics["vsDefaultHardeningDeltaPct"] == -100.0


def test_zero_ref_risk_zero_profile_risk_gives_zero_delta():
    ref = _profile("SCMP_ACT_ERRNO")
    ref_states, ref_risk = reference_states_and_risk(ref)
    p = _profile("SCMP_ACT_ERRNO")
    metrics = score_profile(p, ref_states, ref_risk)
    assert metrics["vsDefaultHardeningDeltaPct"] == 0.0


# ---------------------------------------------------------------------------
# Improved / regressed syscall tracking
# ---------------------------------------------------------------------------

def test_improved_syscall_detected():
    """A syscall moved from allowed (ref) to blocked (profile) → improvedSyscalls."""
    ref_rules = [_rule(["ptrace"], "SCMP_ACT_ALLOW")]
    ref = _profile("SCMP_ACT_ERRNO", ref_rules)
    ref_states, ref_risk = reference_states_and_risk(ref)

    p = _profile("SCMP_ACT_ERRNO")  # blocks ptrace via default
    metrics = score_profile(p, ref_states, ref_risk)
    assert "ptrace" in metrics["improvedSyscalls"]
    assert "ptrace" not in metrics["regressedSyscalls"]


def test_regressed_syscall_detected():
    """A syscall moved from blocked (ref) to allowed (profile) → regressedSyscalls."""
    ref = _profile("SCMP_ACT_ERRNO")  # blocks all by default
    ref_states, ref_risk = reference_states_and_risk(ref)

    p_rules = [_rule(["mount"], "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", p_rules)
    metrics = score_profile(p, ref_states, ref_risk)
    assert "mount" in metrics["regressedSyscalls"]
    assert "mount" not in metrics["improvedSyscalls"]


# ---------------------------------------------------------------------------
# Determinism: sorted lists, stable rounding
# ---------------------------------------------------------------------------

def test_improved_syscalls_sorted():
    ref_rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    ref = _profile("SCMP_ACT_ERRNO", ref_rules)
    ref_states, ref_risk = reference_states_and_risk(ref)

    p = _profile("SCMP_ACT_ERRNO")
    metrics = score_profile(p, ref_states, ref_risk)
    assert metrics["improvedSyscalls"] == sorted(metrics["improvedSyscalls"])


def test_regressed_syscalls_sorted():
    ref = _profile("SCMP_ACT_ERRNO")
    ref_states, ref_risk = reference_states_and_risk(ref)

    p_rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", p_rules)
    metrics = score_profile(p, ref_states, ref_risk)
    assert metrics["regressedSyscalls"] == sorted(metrics["regressedSyscalls"])


def test_delta_pct_rounded_to_one_decimal():
    ref_rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    ref = _profile("SCMP_ACT_ERRNO", ref_rules)
    ref_states, ref_risk = reference_states_and_risk(ref)

    # Block exactly one syscall with weight 2.0 (acct)
    rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW"), _rule(["acct"], "SCMP_ACT_ERRNO")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    metrics = score_profile(p, ref_states, ref_risk)

    val = metrics["vsDefaultHardeningDeltaPct"]
    assert val == round(val, 1)


def test_score_profile_stable_across_runs():
    ref_rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    ref = _profile("SCMP_ACT_ERRNO", ref_rules)
    ref_states, ref_risk = reference_states_and_risk(ref)

    p_rules = [_rule(["bpf", "mount", "ptrace"], "SCMP_ACT_ERRNO")]
    p = _profile("SCMP_ACT_ALLOW", p_rules)

    results = [score_profile(p, ref_states, ref_risk) for _ in range(5)]
    for r in results[1:]:
        assert r == results[0], "score_profile must be deterministic"


# ---------------------------------------------------------------------------
# vs-none coverage
# ---------------------------------------------------------------------------

def test_full_block_gives_100_pct_coverage():
    rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ERRNO")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    ref = _profile("SCMP_ACT_ERRNO")
    ref_states, ref_risk = reference_states_and_risk(ref)
    metrics = score_profile(p, ref_states, ref_risk)
    assert metrics["vsNoneCoveragePct"] == 100.0


def test_full_allow_gives_0_pct_coverage():
    rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    ref = _profile("SCMP_ACT_ERRNO")
    ref_states, ref_risk = reference_states_and_risk(ref)
    metrics = score_profile(p, ref_states, ref_risk)
    assert metrics["vsNoneCoveragePct"] == 0.0
    assert metrics["dangerousBlockedCount"] == 0
    assert len(metrics["dangerousAllowedUnconditionally"]) == len(DANGEROUS_SYSCALLS)


def test_dangerous_allowed_unconditionally_sorted():
    rules = [_rule(list(DANGEROUS_SYSCALLS), "SCMP_ACT_ALLOW")]
    p = _profile("SCMP_ACT_ERRNO", rules)
    ref = _profile("SCMP_ACT_ERRNO")
    ref_states, ref_risk = reference_states_and_risk(ref)
    metrics = score_profile(p, ref_states, ref_risk)
    lst = metrics["dangerousAllowedUnconditionally"]
    assert lst == sorted(lst)


# ---------------------------------------------------------------------------
# Threat V2 scoring model
# ---------------------------------------------------------------------------

class TestThreatV2Scoring:
    """Tests for the threat_v2 Attack Surface and Dangerous Exposure scores."""

    def test_as_perfect_deny_default(self):
        """Profile with defaultAction=DENY and no allowlist -> AS=100.0."""
        p = _profile("SCMP_ACT_ERRNO")
        assert score_attack_surface(p) == 100.0

    def test_as_permissive_default(self):
        """Profile with defaultAction=ALLOW and no denylist -> AS=0.0."""
        p = _profile("SCMP_ACT_ALLOW")
        assert score_attack_surface(p) == 0.0

    def test_as_restrictive_with_allowlist(self):
        """Profile with defaultAction=DENY allowing 46 syscalls -> AS ~ 90.0."""
        fake_syscalls = [f"sys_{i}" for i in range(46)]
        p = _profile("SCMP_ACT_ERRNO", [_rule(fake_syscalls, "SCMP_ACT_ALLOW")])
        result = score_attack_surface(p)
        expected = round((1 - 46 / TOTAL_KNOWN_SYSCALLS) * 100, 1)
        assert result == pytest.approx(expected, abs=0.1)

    def test_de_all_clean(self):
        """Profile blocking all dangerous syscalls -> DE=0.0."""
        p = _profile("SCMP_ACT_ERRNO", [_rule(list(ALL_DANGEROUS_V2), "SCMP_ACT_ERRNO")])
        assert score_dangerous_exposure(p) == 0.0

    def test_de_all_t1_open(self):
        """Profile allowing all T1 syscalls -> DE=-60.0."""
        rules = [
            _rule(list(ALL_DANGEROUS_V2 - set(TIER1)), "SCMP_ACT_ERRNO"),
            _rule(TIER1, "SCMP_ACT_ALLOW"),
        ]
        p = _profile("SCMP_ACT_ERRNO", rules)
        assert score_dangerous_exposure(p) == -60.0

    def test_de_all_t2_open(self):
        """Profile allowing all T2 syscalls -> DE=-30.0."""
        rules = [
            _rule(list(ALL_DANGEROUS_V2 - set(TIER2)), "SCMP_ACT_ERRNO"),
            _rule(TIER2, "SCMP_ACT_ALLOW"),
        ]
        p = _profile("SCMP_ACT_ERRNO", rules)
        assert score_dangerous_exposure(p) == -30.0

    def test_de_all_t3_open(self):
        """Profile allowing all T3 syscalls -> DE=-10.0."""
        rules = [
            _rule(list(ALL_DANGEROUS_V2 - set(TIER3)), "SCMP_ACT_ERRNO"),
            _rule(TIER3, "SCMP_ACT_ALLOW"),
        ]
        p = _profile("SCMP_ACT_ERRNO", rules)
        assert score_dangerous_exposure(p) == -10.0

    def test_de_all_open(self):
        """Profile allowing all dangerous syscalls -> DE=-100.0."""
        p = _profile("SCMP_ACT_ERRNO", [_rule(list(ALL_DANGEROUS_V2), "SCMP_ACT_ALLOW")])
        assert score_dangerous_exposure(p) == -100.0

    def test_de_conditional_is_10pct(self):
        """Profile with one T1 syscall conditional -> DE = -(60/9 * 0.1) rounded."""
        rules = [
            _rule(list(ALL_DANGEROUS_V2 - {"bpf"}), "SCMP_ACT_ERRNO"),
            _rule(["bpf"], "SCMP_ACT_ALLOW",
                  args=[{"index": 0, "op": "SCMP_CMP_EQ", "value": 0}]),
        ]
        p = _profile("SCMP_ACT_ERRNO", rules)
        expected = -round(TIER1_BUDGET / len(TIER1) * 0.1, 1)
        assert score_dangerous_exposure(p) == pytest.approx(expected, abs=0.05)

    def test_score_profile_includes_new_fields(self):
        """score_profile() output includes attackSurfaceScore and dangerousExposureScore."""
        ref = _profile("SCMP_ACT_ERRNO")
        ref_states, ref_risk = reference_states_and_risk(ref)
        p = _profile("SCMP_ACT_ERRNO")
        metrics = score_profile(p, ref_states, ref_risk)
        assert "attackSurfaceScore" in metrics
        assert "dangerousExposureScore" in metrics
        assert isinstance(metrics["attackSurfaceScore"], float)
        assert isinstance(metrics["dangerousExposureScore"], float)
