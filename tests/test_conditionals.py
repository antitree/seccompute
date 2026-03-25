"""Behavioral tests for conditional analysis per SPEC.md."""
import pytest
from seccompute import score_profile
from seccompute.conditionals import analyze_conditionals, resolve_effective_states
from tests.conftest import make_profile, allow_rule


class TestEffectiveStateResolution:
    def test_unconditional_allow(self):
        p = make_profile(rules=[allow_rule("bpf")])
        states = resolve_effective_states(p, frozenset(["bpf"]))
        assert states["bpf"] == "allowed"

    def test_conditional_allow_with_caps_no_context(self):
        """Cap-gated allow with no caps context is ignored — falls to default (blocked)."""
        p = make_profile(rules=[
            allow_rule("bpf", includes={"caps": ["CAP_BPF"]}),
        ])
        states = resolve_effective_states(p, frozenset(["bpf"]), granted_caps=None)
        assert states["bpf"] == "blocked"

    def test_conditional_allow_with_caps_granted(self):
        """Cap-gated allow with cap granted resolves to allowed."""
        p = make_profile(rules=[
            allow_rule("bpf", includes={"caps": ["CAP_BPF"]}),
        ])
        states = resolve_effective_states(p, frozenset(["bpf"]), granted_caps=frozenset({"CAP_BPF"}))
        assert states["bpf"] == "allowed"

    def test_conditional_allow_with_args(self):
        p = make_profile(rules=[
            allow_rule("clone", args=[{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}]),
        ])
        states = resolve_effective_states(p, frozenset(["clone"]))
        assert states["clone"] == "conditional"

    def test_deny_with_cap_exclude_is_conditional(self):
        p = make_profile(rules=[{
            "names": ["mount"],
            "action": "SCMP_ACT_ERRNO",
            "excludes": {"caps": ["CAP_SYS_ADMIN"]},
        }])
        states = resolve_effective_states(p, frozenset(["mount"]))
        assert states["mount"] == "conditional"

    def test_deny_with_args_stays_blocked(self):
        p = make_profile(rules=[{
            "names": ["clone"],
            "action": "SCMP_ACT_ERRNO",
            "args": [{"index": 0, "value": 0x10000000, "op": "SCMP_CMP_MASKED_EQ"}],
        }])
        states = resolve_effective_states(p, frozenset(["clone"]))
        assert states["clone"] == "blocked"

    def test_default_allows(self):
        p = make_profile("SCMP_ACT_ALLOW")
        states = resolve_effective_states(p, frozenset(["bpf"]))
        assert states["bpf"] == "allowed"

    def test_default_blocks(self):
        p = make_profile("SCMP_ACT_ERRNO")
        states = resolve_effective_states(p, frozenset(["bpf"]))
        assert states["bpf"] == "blocked"

    def test_unconditional_allow_wins_over_block(self):
        p = make_profile(rules=[
            {"names": ["bpf"], "action": "SCMP_ACT_ERRNO"},
            allow_rule("bpf"),
        ])
        states = resolve_effective_states(p, frozenset(["bpf"]))
        assert states["bpf"] == "allowed"


class TestConditionalFindings:
    def test_cap_gate_produces_finding(self):
        p = make_profile(rules=[
            allow_rule("bpf", includes={"caps": ["CAP_BPF"]}),
        ])
        findings = analyze_conditionals(p)
        assert any(f.syscall == "bpf" and f.condition_type == "capability_gate" for f in findings)

    def test_arg_filter_produces_finding(self):
        p = make_profile(rules=[
            allow_rule("clone", args=[{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}]),
        ])
        findings = analyze_conditionals(p)
        assert any(f.syscall == "clone" and f.condition_type == "argument_filter" for f in findings)
