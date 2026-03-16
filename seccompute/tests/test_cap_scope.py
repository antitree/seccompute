"""Tests for capability-aware scoring mode."""
from __future__ import annotations

import pytest

from seccompute.cap_scope import get_scope_for_caps
from seccompute.scoring import score_profile
from seccompute.weights_v2 import TIER1, TIER1_BUDGET


def _profile(default="SCMP_ACT_ERRNO", rules=None):
    return {"defaultAction": default, "syscalls": rules or []}


def _rule(names, action, **kwargs):
    r = {"names": names, "action": action}
    r.update(kwargs)
    return r


def _allow(*names):
    return _rule(list(names), "SCMP_ACT_ALLOW")


def _block(*names):
    return _rule(list(names), "SCMP_ACT_ERRNO")


def _conditional_allow(*names, caps=None):
    """Allow with cap include gate (conditional)."""
    return _rule(list(names), "SCMP_ACT_ALLOW", includes={"caps": caps or []})


# ---------------------------------------------------------------------------
# get_scope_for_caps tests
# ---------------------------------------------------------------------------

class TestGetScopeForCaps:
    def test_ptrace_in_primary(self):
        primary, related = get_scope_for_caps(["CAP_SYS_PTRACE"])
        assert "ptrace" in primary
        assert "process_vm_readv" in primary
        assert "process_vm_writev" in primary

    def test_sys_admin_primary(self):
        primary, related = get_scope_for_caps(["CAP_SYS_ADMIN"])
        # init_module is under CAP_SYS_MODULE, not CAP_SYS_ADMIN
        assert "mount" in primary
        assert "unshare" in primary
        assert "setns" in primary

    def test_sys_admin_related(self):
        primary, related = get_scope_for_caps(["CAP_SYS_ADMIN"])
        # bpf is primary under CAP_SYS_ADMIN (Moby/containerd gate it there)
        assert "bpf" in primary
        assert "pivot_root" in related

    def test_empty_caps(self):
        primary, related = get_scope_for_caps([])
        assert primary == set()
        assert related == set()

    def test_union_and_related_excludes_primary(self):
        """CAP_SYS_PTRACE + CAP_SYS_MODULE should union primaries;
        related should not include anything already in primary."""
        primary, related = get_scope_for_caps(["CAP_SYS_PTRACE", "CAP_SYS_MODULE"])
        assert "ptrace" in primary
        assert "init_module" in primary
        assert "delete_module" in primary
        # No overlap
        assert len(primary & related) == 0

    def test_unknown_cap_returns_empty(self):
        primary, related = get_scope_for_caps(["CAP_NONEXISTENT"])
        assert primary == set()
        assert related == set()

    def test_bpf_in_primary_for_both_cap_bpf_and_cap_sys_admin(self):
        """bpf is primary under both CAP_BPF and CAP_SYS_ADMIN (Moby/containerd gate it there).
        When both caps are declared, bpf should be in primary, not related."""
        primary, related = get_scope_for_caps(["CAP_SYS_ADMIN", "CAP_BPF"])
        assert "bpf" in primary
        assert "bpf" not in related


# ---------------------------------------------------------------------------
# Elevated scoring mode tests
# ---------------------------------------------------------------------------

class TestElevatedScoring:
    def test_elevated_mode_flag(self):
        p = _profile(rules=[_allow("ptrace")])
        result = score_profile(p, granted_caps=["CAP_SYS_PTRACE"])
        assert result.scoring_mode == "elevated"
        assert result.granted_caps == ["CAP_SYS_PTRACE"]

    def test_default_mode_flag(self):
        p = _profile(rules=[_allow("ptrace")])
        result = score_profile(p)
        assert result.scoring_mode == "default"
        assert result.granted_caps == []

    def test_ptrace_allowed_scores_higher_with_cap(self):
        """Allowing ptrace with CAP_SYS_PTRACE declared should score higher
        (less deduction) than without."""
        p = _profile(rules=[_allow("ptrace")])
        result_default = score_profile(p)
        result_elevated = score_profile(p, granted_caps=["CAP_SYS_PTRACE"])
        assert result_elevated.score > result_default.score

    def test_ptrace_conditional_scores_higher_with_cap(self):
        """Conditional ptrace with declared cap should score much higher."""
        p = _profile(rules=[_conditional_allow("ptrace", caps=["CAP_SYS_PTRACE"])])
        result_default = score_profile(p)
        result_elevated = score_profile(p, granted_caps=["CAP_SYS_PTRACE"])
        assert result_elevated.score > result_default.score

    def test_out_of_scope_still_full_penalty(self):
        """A Tier 1 syscall not justified by declared caps gets full penalty in elevated mode."""
        # bpf is Tier 1, not in CAP_SYS_PTRACE scope
        p = _profile(rules=[_allow("bpf")])
        result_default = score_profile(p)
        result_elevated = score_profile(p, granted_caps=["CAP_SYS_PTRACE"])
        assert result_default.score == result_elevated.score

    def test_metadata_includes_mode(self):
        p = _profile(rules=[_allow("ptrace")])
        result = score_profile(p, granted_caps=["CAP_SYS_PTRACE"])
        assert result.metadata["scoring_mode"] == "elevated"
        assert result.metadata["granted_caps"] == ["CAP_SYS_PTRACE"]

    def test_related_syscall_partial_reduction(self):
        """Related syscalls get partial reduction, less than primary."""
        # pivot_root is related to CAP_SYS_ADMIN, not primary
        p = _profile(rules=[_allow("pivot_root")])
        result_no_cap = score_profile(p)
        result_with_cap = score_profile(p, granted_caps=["CAP_SYS_ADMIN"])
        # Related gets 0.7x vs 1.0x, so should score higher
        assert result_with_cap.score > result_no_cap.score

    def test_elevated_vs_default_different_scores(self):
        """Same profile, different modes, clearly different scores."""
        p = _profile(rules=[
            _allow("ptrace", "process_vm_readv"),
            _allow("mount", "unshare"),
        ])
        result_default = score_profile(p)
        result_elevated = score_profile(p, granted_caps=["CAP_SYS_PTRACE", "CAP_SYS_ADMIN"])
        assert result_elevated.score != result_default.score
        assert result_elevated.score > result_default.score


# ---------------------------------------------------------------------------
# Default mode: Tier 1 conditional multiplier change
# ---------------------------------------------------------------------------

class TestDefaultModeTier1Conditional:
    def test_tier1_conditional_uses_075_multiplier(self):
        """In default mode, Tier 1 conditional should use 0.75x, not 0.5x."""
        p = _profile(rules=[_conditional_allow("bpf", caps=["CAP_SYS_ADMIN"])])
        result = score_profile(p)
        # bpf is Tier 1. With 0.75x: deduction = (60/9) * 0.75
        full_deduction = TIER1_BUDGET / len(TIER1)
        expected = round(100 - full_deduction * 0.75)
        assert result.score == expected

    def test_tier2_conditional_still_05(self):
        """Tier 2 conditional should still use 0.5x in default mode."""
        # mount is Tier 2
        p = _profile(rules=[_conditional_allow("mount", caps=["CAP_SYS_ADMIN"])])
        result = score_profile(p)
        # Find mount's detail
        mount_detail = [sd for sd in result.syscall_details if sd.name == "mount"][0]
        assert mount_detail.multiplier == 0.5
