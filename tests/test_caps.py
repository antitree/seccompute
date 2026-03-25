"""Tests for --caps capability-gate resolution feature."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from seccompute.conditionals import analyze_conditionals, resolve_effective_states
from seccompute.model import ConditionalFinding
from seccompute.scoring import score_profile
from seccompute.__main__ import main, _parse_caps


# ---------------------------------------------------------------------------
# Helper: minimal profile builder
# ---------------------------------------------------------------------------

def _profile(
    syscalls: list[dict],
    default: str = "SCMP_ACT_ERRNO",
) -> dict:
    return {"defaultAction": default, "syscalls": syscalls}


def _cap_gated_allow(names: list[str], caps: list[str]) -> dict:
    return {
        "names": names,
        "action": "SCMP_ACT_ALLOW",
        "includes": {"caps": caps},
    }


def _unconditional_allow(names: list[str]) -> dict:
    return {"names": names, "action": "SCMP_ACT_ALLOW"}


def _arg_filtered_allow(names: list[str]) -> dict:
    return {
        "names": names,
        "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}],
    }


# ===========================================================================
# resolve_effective_states tests
# ===========================================================================

class TestCapGateResolveEffectiveStates:
    """Cap-gate handling in resolve_effective_states."""

    def test_cap_gate_ignored_when_no_caps_context(self):
        profile = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        states = resolve_effective_states(profile, frozenset({"bpf"}), granted_caps=None)
        assert states["bpf"] == "blocked"

    def test_cap_gate_allowed_when_cap_granted(self):
        profile = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        states = resolve_effective_states(profile, frozenset({"bpf"}), granted_caps=frozenset({"CAP_BPF"}))
        assert states["bpf"] == "allowed"

    def test_cap_gate_blocked_when_cap_not_granted(self):
        profile = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        states = resolve_effective_states(profile, frozenset({"bpf"}), granted_caps=frozenset({"CAP_SYS_ADMIN"}))
        assert states["bpf"] == "blocked"

    def test_cap_gate_empty_caps_blocks_all(self):
        profile = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        states = resolve_effective_states(profile, frozenset({"bpf"}), granted_caps=frozenset())
        assert states["bpf"] == "blocked"

    def test_cap_gate_multiple_caps_required_both_granted(self):
        profile = _profile([_cap_gated_allow(["mount"], ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"])])
        states = resolve_effective_states(
            profile, frozenset({"mount"}),
            granted_caps=frozenset({"CAP_SYS_ADMIN", "CAP_NET_ADMIN"}),
        )
        assert states["mount"] == "allowed"

    def test_cap_gate_multiple_caps_required_partial_granted(self):
        profile = _profile([_cap_gated_allow(["mount"], ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"])])
        states = resolve_effective_states(
            profile, frozenset({"mount"}),
            granted_caps=frozenset({"CAP_SYS_ADMIN"}),
        )
        assert states["mount"] == "blocked"

    def test_non_cap_conditional_unaffected_by_caps_context(self):
        profile = _profile([_arg_filtered_allow(["clone"])])
        states = resolve_effective_states(
            profile, frozenset({"clone"}),
            granted_caps=frozenset({"CAP_BPF"}),
        )
        assert states["clone"] == "conditional"


# ===========================================================================
# ConditionalFinding.resolved field tests
# ===========================================================================

class TestConditionalFindingResolved:
    """The resolved field on ConditionalFinding for cap gates."""

    def test_cap_finding_resolved_none_when_no_caps(self):
        profile = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        findings = analyze_conditionals(profile, granted_caps=None)
        cap_findings = [f for f in findings if f.condition_type == "capability_gate"]
        assert len(cap_findings) == 1
        assert cap_findings[0].resolved is None

    def test_cap_finding_resolved_true_when_granted(self):
        profile = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        findings = analyze_conditionals(profile, granted_caps=frozenset({"CAP_BPF"}))
        cap_findings = [f for f in findings if f.condition_type == "capability_gate"]
        assert len(cap_findings) == 1
        assert cap_findings[0].resolved is True

    def test_cap_finding_resolved_false_when_not_granted(self):
        profile = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        findings = analyze_conditionals(profile, granted_caps=frozenset({"CAP_SYS_ADMIN"}))
        cap_findings = [f for f in findings if f.condition_type == "capability_gate"]
        assert len(cap_findings) == 1
        assert cap_findings[0].resolved is False


# ===========================================================================
# Score-level integration tests
# ===========================================================================

class TestScoreIntegration:
    """Integration tests for score_profile with granted_caps."""

    def test_docker_containerd_equivalence(self):
        """Cap-gated bpf with no caps context scores same as bpf not listed."""
        docker = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        containerd = _profile([])  # bpf not listed, default blocks it
        s_docker = score_profile(docker, granted_caps=None).score
        s_containerd = score_profile(containerd, granted_caps=None).score
        assert s_docker == s_containerd

    def test_score_higher_with_cap_granted(self):
        """Granting the cap makes bpf 'allowed', lowering the score (worse)."""
        profile = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        score_no_caps = score_profile(profile, granted_caps=None).score
        score_with_caps = score_profile(profile, granted_caps=frozenset({"CAP_BPF"})).score
        # With cap granted, bpf is allowed -> more deduction -> lower score
        assert score_with_caps < score_no_caps

    def test_score_with_caps_matches_unconditional_allow(self):
        """Cap-gated allow with cap granted == unconditional allow in score."""
        docker = _profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])
        flat = _profile([_unconditional_allow(["bpf"])])
        s_docker = score_profile(docker, granted_caps=frozenset({"CAP_BPF"})).score
        s_flat = score_profile(flat).score
        assert s_docker == s_flat


# ===========================================================================
# Cap name normalization / parse_caps tests
# ===========================================================================

class TestParseCaps:
    """Tests for _parse_caps helper."""

    def test_caps_normalized_to_uppercase(self):
        result = _parse_caps("cap_bpf,CAP_SYS_ADMIN")
        assert result == frozenset({"CAP_BPF", "CAP_SYS_ADMIN"})

    def test_empty_caps_string_produces_empty_frozenset(self):
        result = _parse_caps("")
        assert result == frozenset()

    def test_none_caps_arg_produces_none(self):
        result = _parse_caps(None)
        assert result is None


# ===========================================================================
# CLI integration tests
# ===========================================================================

class TestCLICaps:
    """CLI --caps flag tests."""

    @pytest.fixture()
    def cap_profile_path(self, tmp_path: Path) -> Path:
        """Write a profile with bpf gated on CAP_BPF."""
        p = tmp_path / "profile.json"
        p.write_text(json.dumps(_profile([_cap_gated_allow(["bpf"], ["CAP_BPF"])])))
        return p

    def test_cli_caps_flag_resolves_conditional(self, cap_profile_path: Path, capsys):
        ret = main([str(cap_profile_path), "--caps", "CAP_BPF", "--format", "json"])
        assert ret == 0
        out = json.loads(capsys.readouterr().out)
        cap_findings = [
            f for f in out["conditional_findings"]
            if f["condition_type"] == "capability_gate" and f["syscall"] == "bpf"
        ]
        assert len(cap_findings) == 1
        assert cap_findings[0]["resolved"] is True

    def test_cli_no_caps_flag_ignores_conditionals(self, cap_profile_path: Path, capsys):
        ret = main([str(cap_profile_path), "--format", "json"])
        assert ret == 0
        out = json.loads(capsys.readouterr().out)
        cap_findings = [
            f for f in out["conditional_findings"]
            if f["condition_type"] == "capability_gate" and f["syscall"] == "bpf"
        ]
        assert len(cap_findings) == 1
        assert cap_findings[0]["resolved"] is None

    def test_cli_empty_caps_flag(self, cap_profile_path: Path, capsys):
        ret = main([str(cap_profile_path), "--caps", "", "--format", "json"])
        assert ret == 0
        out = json.loads(capsys.readouterr().out)
        cap_findings = [
            f for f in out["conditional_findings"]
            if f["condition_type"] == "capability_gate" and f["syscall"] == "bpf"
        ]
        assert len(cap_findings) == 1
        assert cap_findings[0]["resolved"] is False
