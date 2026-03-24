"""Behavioral tests for grading and forced-failure per SPEC.md."""
import pytest
from seccompute import score_profile
from tests.conftest import make_profile, allow_rule


class TestGrading:
    def test_grade_A(self):
        result = score_profile(make_profile("SCMP_ACT_ERRNO"))
        assert result.grade == "A"
        assert result.score >= 90

    def test_grade_F_for_allow_all(self):
        result = score_profile(make_profile("SCMP_ACT_ALLOW"))
        assert result.grade == "F"
        assert result.score < 60


class TestForcedFailure:
    def test_t1_unconditional_forces_F(self):
        result = score_profile(make_profile(rules=[allow_rule("ptrace")]))
        assert result.forced_failure is True
        assert result.grade == "F"
        assert any("ptrace" in r for r in result.forced_failure_reasons)

    def test_t1_conditional_no_forced_F(self):
        result = score_profile(make_profile(rules=[
            allow_rule("ptrace", includes={"caps": ["CAP_SYS_PTRACE"]}),
        ]))
        assert result.forced_failure is False

    def test_t1_blocked_no_forced_F(self):
        result = score_profile(make_profile("SCMP_ACT_ERRNO"))
        assert result.forced_failure is False
        assert result.forced_failure_reasons == []

    def test_t2_unconditional_no_forced_F(self):
        result = score_profile(make_profile(rules=[allow_rule("mount")]))
        assert result.forced_failure is False

    def test_default_allow_forces_F(self):
        result = score_profile(make_profile("SCMP_ACT_ALLOW"))
        assert result.forced_failure is True
        assert len(result.forced_failure_reasons) > 0

    def test_multiple_t1_all_listed(self):
        result = score_profile(make_profile(rules=[
            allow_rule("ptrace", "bpf", "kexec_load"),
        ]))
        assert result.forced_failure is True
        reasons_text = " ".join(result.forced_failure_reasons)
        assert "ptrace" in reasons_text
        assert "bpf" in reasons_text
        assert "kexec_load" in reasons_text


class TestAnnotationOverrides:
    def test_annotation_lifts_forced_F(self):
        result = score_profile(make_profile(
            rules=[allow_rule("ptrace")],
            x_seccompute={"intent": {"syscalls": {
                "ptrace": {"justification": "Required for debugger", "confined": False},
            }}},
        ))
        assert result.forced_failure is False
        assert "ptrace" in result.annotation_overrides

    def test_partial_annotation_still_forced_F(self):
        result = score_profile(make_profile(
            rules=[allow_rule("ptrace", "bpf")],
            x_seccompute={"intent": {"syscalls": {
                "ptrace": {"justification": "Needed for debugger"},
            }}},
        ))
        assert result.forced_failure is True
        reasons_text = " ".join(result.forced_failure_reasons)
        assert "bpf" in reasons_text
        assert "ptrace" not in reasons_text

    def test_annotation_does_not_change_score(self):
        p_no_ann = make_profile(rules=[allow_rule("ptrace")])
        p_ann = make_profile(
            rules=[allow_rule("ptrace")],
            x_seccompute={"intent": {"syscalls": {
                "ptrace": {"justification": "Debugger"},
            }}},
        )
        assert score_profile(p_no_ann).score == score_profile(p_ann).score

    def test_legacy_allow_list_overrides(self):
        result = score_profile(make_profile(
            rules=[allow_rule("ptrace")],
            x_seccompute={"allow": ["ptrace"]},
        ))
        assert result.forced_failure is False

    def test_empty_justification_does_not_override(self):
        result = score_profile(make_profile(
            rules=[allow_rule("ptrace")],
            x_seccompute={"intent": {"syscalls": {
                "ptrace": {"justification": "", "confined": False},
            }}},
        ))
        assert result.forced_failure is True
