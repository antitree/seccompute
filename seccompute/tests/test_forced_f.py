"""Tests for forced F grade when T1 syscalls are unconditionally allowed."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.scoring import score_profile
from seccompute.grader import compute_grade, render_grade


def _profile(default_action="SCMP_ACT_ERRNO", rules=None, x_seccompute=None):
    p = {"defaultAction": default_action, "syscalls": rules or []}
    if x_seccompute is not None:
        p["x-seccompute"] = x_seccompute
    return p


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
# Forced F triggers
# ---------------------------------------------------------------------------

class TestForcedFTrigger:
    """Unconditional ALLOW of T1 syscalls forces grade to F."""

    def test_ptrace_unconditional_allow_forces_f(self):
        p = _profile(rules=[_rule(["ptrace"], "SCMP_ACT_ALLOW")])
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is True
        assert g["letter"] == "F"
        assert "ptrace" in g["forced_f_syscalls"]

    def test_bpf_unconditional_allow_forces_f(self):
        p = _profile(rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")])
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is True
        assert "bpf" in g["forced_f_syscalls"]

    def test_multiple_t1_unconditional(self):
        p = _profile(rules=[_rule(["ptrace", "bpf", "kexec_load"], "SCMP_ACT_ALLOW")])
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is True
        assert set(g["forced_f_syscalls"]) == {"ptrace", "bpf", "kexec_load"}

    def test_all_dangerous_allowed_via_default_action(self):
        """defaultAction=ALLOW means all T1 are unconditionally allowed."""
        p = _profile("SCMP_ACT_ALLOW")
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is True
        assert len(g["forced_f_syscalls"]) > 0


# ---------------------------------------------------------------------------
# Forced F does NOT trigger
# ---------------------------------------------------------------------------

class TestForcedFNotTriggered:
    """Conditional allows and blocked T1 syscalls should not force F."""

    def test_t1_blocked_no_forced_f(self):
        """All T1 blocked by default -> no forced F."""
        p = _profile("SCMP_ACT_ERRNO")
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is False
        assert g["forced_f_syscalls"] == []

    def test_t1_conditional_no_forced_f(self):
        """T1 with arg filter (conditional) should NOT force F."""
        p = _profile(rules=[_rule(
            ["ptrace"], "SCMP_ACT_ALLOW",
            args=[{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}],
        )])
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is False

    def test_t1_conditional_cap_gate_no_forced_f(self):
        """T1 with capability gate (conditional) should NOT force F."""
        p = _profile(rules=[_rule(
            ["ptrace"], "SCMP_ACT_ALLOW",
            includes={"caps": ["CAP_SYS_PTRACE"]},
        )])
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is False

    def test_only_t2_allowed_no_forced_f(self):
        """T2 unconditional allow should not force F (only T1 matters)."""
        p = _profile(rules=[_rule(["mount"], "SCMP_ACT_ALLOW")])
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is False


# ---------------------------------------------------------------------------
# x-seccompute annotation override
# ---------------------------------------------------------------------------

class TestXSeccomputeOverride:
    """x-seccompute annotation acknowledging T1 risk lifts forced F."""

    def test_acknowledged_t1_no_forced_f(self):
        p = _profile(
            rules=[_rule(["ptrace"], "SCMP_ACT_ALLOW")],
            x_seccompute={"allow": ["ptrace"]},
        )
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is False

    def test_partial_acknowledgement_still_forced_f(self):
        """Only ptrace acknowledged but bpf also allowed -> still forced F."""
        p = _profile(
            rules=[_rule(["ptrace", "bpf"], "SCMP_ACT_ALLOW")],
            x_seccompute={"allow": ["ptrace"]},
        )
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is True
        assert g["forced_f_syscalls"] == ["bpf"]
        assert "ptrace" not in g["forced_f_syscalls"]

    def test_all_acknowledged_no_forced_f(self):
        p = _profile(
            rules=[_rule(["ptrace", "bpf"], "SCMP_ACT_ALLOW")],
            x_seccompute={"allow": ["ptrace", "bpf"]},
        )
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is False

    def test_non_t1_in_annotation_ignored(self):
        """x-seccompute listing a T2 syscall shouldn't affect T1 forced F."""
        p = _profile(
            rules=[_rule(["ptrace", "mount"], "SCMP_ACT_ALLOW")],
            x_seccompute={"allow": ["mount"]},
        )
        result = score_profile(p)
        g = compute_grade(result)
        assert g["forced_f"] is True
        assert "ptrace" in g["forced_f_syscalls"]


# ---------------------------------------------------------------------------
# Render output includes warning
# ---------------------------------------------------------------------------

class TestForcedFRenderWarning:
    """All render styles should include the forced F warning text."""

    def _profile_with_t1_allow(self):
        return _profile(rules=[_rule(["ptrace", "bpf"], "SCMP_ACT_ALLOW")])

    def test_render_v1_warning(self):
        result = score_profile(self._profile_with_t1_allow())
        output = render_grade(result, style=1)
        assert "FORCED F" in output
        assert "ptrace" in output

    def test_render_v2_warning(self):
        result = score_profile(self._profile_with_t1_allow())
        output = render_grade(result, style=2)
        assert "FORCED F" in output

    def test_render_v3_warning(self):
        result = score_profile(self._profile_with_t1_allow())
        output = render_grade(result, style=3)
        assert "FORCED F" in output

    def test_render_v4_warning(self):
        result = score_profile(self._profile_with_t1_allow())
        output = render_grade(result, style=4)
        assert "FORCED F" in output

    def test_render_no_warning_when_not_forced(self):
        result = score_profile(_profile("SCMP_ACT_ERRNO"))
        for style in (1, 2, 3, 4):
            output = render_grade(result, style=style)
            assert "FORCED F" not in output
