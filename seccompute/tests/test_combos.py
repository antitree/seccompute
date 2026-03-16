"""Tests for the combo rule engine (combos.py + combo_rules.yaml)."""

from __future__ import annotations

import pytest

from seccompute.combos import ComboFinding, evaluate_combos
from seccompute.scoring import ScoringResult, score_profile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _profile(default_action="SCMP_ACT_ERRNO", rules=None):
    return {"defaultAction": default_action, "syscalls": rules or []}


def _allow(*syscalls):
    return {"names": list(syscalls), "action": "SCMP_ACT_ALLOW"}


def _block(*syscalls):
    return {"names": list(syscalls), "action": "SCMP_ACT_ERRNO"}


def _states_for(profile):
    """Extract syscall states from a scored profile."""
    result = score_profile(profile)
    return {sd.name: sd.state for sd in result.syscall_details}


# ---------------------------------------------------------------------------
# evaluate_combos() unit tests
# ---------------------------------------------------------------------------

class TestEvalCombosIoUringNetwork:
    """COMBO-io-uring-network-bypass fires when io_uring is allowed
    AND at least one network syscall is blocked."""

    def test_fires_when_iouring_allowed_and_network_blocked(self):
        profile = _profile(rules=[
            _allow("io_uring_setup", "io_uring_enter"),
            _block("socket", "connect"),
        ])
        # Build minimal states: io_uring allowed, network blocked by default
        states = {
            "io_uring_setup": "allowed",
            "io_uring_enter": "allowed",
        }
        findings = evaluate_combos(profile, states)
        ids = [f.id for f in findings]
        assert "COMBO-io-uring-network-bypass" in ids

    def test_does_not_fire_when_iouring_setup_missing(self):
        """Only io_uring_enter allowed — setup missing, should not fire."""
        profile = _profile(rules=[_allow("io_uring_enter")])
        states = {"io_uring_enter": "allowed"}
        findings = evaluate_combos(profile, states)
        ids = [f.id for f in findings]
        assert "COMBO-io-uring-network-bypass" not in ids

    def test_does_not_fire_when_no_network_blocked(self):
        """io_uring allowed but all network syscalls are also allowed — no bypass."""
        network = [
            "socket", "socketpair", "connect", "bind", "accept", "accept4",
            "send", "sendto", "sendmsg", "sendmmsg",
            "recv", "recvfrom", "recvmsg", "recvmmsg",
            "shutdown", "getsockopt", "setsockopt",
        ]
        profile = _profile(rules=[
            _allow("io_uring_setup", "io_uring_enter", *network),
        ])
        # Pass full states so evaluator sees all network syscalls as allowed
        states = {sc: "allowed" for sc in network}
        states["io_uring_setup"] = "allowed"
        states["io_uring_enter"] = "allowed"
        findings = evaluate_combos(profile, states)
        ids = [f.id for f in findings]
        assert "COMBO-io-uring-network-bypass" not in ids

    def test_does_not_fire_when_both_blocked(self):
        """io_uring itself blocked — should never fire."""
        profile = _profile(rules=[_block("socket", "connect")])
        states = {
            "io_uring_setup": "blocked",
            "io_uring_enter": "blocked",
        }
        findings = evaluate_combos(profile, states)
        assert findings == []

    def test_finding_contains_correct_bypasses_blocked(self):
        """bypasses_blocked should list only the blocked network syscalls."""
        profile = _profile(rules=[
            _allow("io_uring_setup", "io_uring_enter"),
            _block("socket", "connect"),
        ])
        states = {
            "io_uring_setup": "allowed",
            "io_uring_enter": "allowed",
        }
        findings = evaluate_combos(profile, states)
        net = next(f for f in findings if f.id == "COMBO-io-uring-network-bypass")
        # socket and connect are blocked in the profile (defaultAction=ERRNO)
        assert "socket" in net.bypasses_blocked
        assert "connect" in net.bypasses_blocked
        # send is not mentioned — blocked by default too
        assert "send" in net.bypasses_blocked

    def test_finding_severity_is_high(self):
        profile = _profile(rules=[
            _allow("io_uring_setup", "io_uring_enter"),
        ])
        states = {"io_uring_setup": "allowed", "io_uring_enter": "allowed"}
        # Need at least one blocked bypass for it to fire
        # defaultAction=ERRNO means network syscalls are blocked
        findings = evaluate_combos(profile, states)
        net_findings = [f for f in findings if f.id == "COMBO-io-uring-network-bypass"]
        assert len(net_findings) == 1
        assert net_findings[0].severity == "HIGH"

    def test_conditional_iouring_still_triggers(self):
        """Conditional io_uring_enter (0.5x) still represents bypass risk."""
        profile = _profile(rules=[
            _allow("io_uring_setup"),
            {"names": ["io_uring_enter"], "action": "SCMP_ACT_ALLOW",
             "args": [{"index": 0, "value": 1, "op": "SCMP_CMP_EQ"}]},
        ])
        states = {
            "io_uring_setup": "allowed",
            "io_uring_enter": "conditional",
        }
        findings = evaluate_combos(profile, states)
        ids = [f.id for f in findings]
        assert "COMBO-io-uring-network-bypass" in ids


class TestEvalCombosIoUringFileIO:
    """COMBO-io-uring-file-io-bypass fires when io_uring is allowed
    AND at least one file I/O syscall is blocked."""

    def test_fires_when_read_blocked(self):
        profile = _profile(rules=[_allow("io_uring_setup", "io_uring_enter")])
        states = {"io_uring_setup": "allowed", "io_uring_enter": "allowed"}
        # defaultAction=ERRNO means read is blocked
        findings = evaluate_combos(profile, states)
        ids = [f.id for f in findings]
        assert "COMBO-io-uring-file-io-bypass" in ids

    def test_does_not_fire_when_all_file_io_allowed(self):
        """If all file I/O syscalls are explicitly allowed, no bypass benefit."""
        file_io = [
            "read", "write", "readv", "writev", "pread64", "pwrite64",
            "preadv", "pwritev", "preadv2", "pwritev2",
            "fsync", "fdatasync", "sync_file_range",
            "fallocate", "fadvise64", "madvise",
        ]
        profile = _profile(rules=[_allow("io_uring_setup", "io_uring_enter", *file_io)])
        # Pass full states so evaluator sees all file I/O as allowed
        states = {sc: "allowed" for sc in file_io}
        states["io_uring_setup"] = "allowed"
        states["io_uring_enter"] = "allowed"
        findings = evaluate_combos(profile, states)
        ids = [f.id for f in findings]
        assert "COMBO-io-uring-file-io-bypass" not in ids


class TestEvalCombosIoUringFilesystem:
    def test_fires_when_openat_blocked(self):
        profile = _profile(rules=[_allow("io_uring_setup", "io_uring_enter")])
        states = {"io_uring_setup": "allowed", "io_uring_enter": "allowed"}
        findings = evaluate_combos(profile, states)
        ids = [f.id for f in findings]
        assert "COMBO-io-uring-filesystem-bypass" in ids

    def test_finding_includes_openat_in_bypasses(self):
        profile = _profile(rules=[_allow("io_uring_setup", "io_uring_enter")])
        states = {"io_uring_setup": "allowed", "io_uring_enter": "allowed"}
        findings = evaluate_combos(profile, states)
        fs = next(f for f in findings if f.id == "COMBO-io-uring-filesystem-bypass")
        assert "openat" in fs.bypasses_blocked


class TestEvalCombosPermissiveDefault:
    """With defaultAction=SCMP_ACT_ALLOW, nothing is blocked, combos should not fire."""

    def test_permissive_default_no_combos(self):
        profile = _profile(
            default_action="SCMP_ACT_ALLOW",
            rules=[_allow("io_uring_setup", "io_uring_enter")],
        )
        states = {"io_uring_setup": "allowed", "io_uring_enter": "allowed"}
        findings = evaluate_combos(profile, states)
        # No syscalls are blocked, so bypass_requires_blocked prevents all combos
        assert findings == []


class TestComboFindingSummary:
    def test_summary_contains_triggered_and_bypassed(self):
        cf = ComboFinding(
            id="COMBO-io-uring-network-bypass",
            name="io_uring network bypass",
            description="test",
            triggered_by=["io_uring_setup", "io_uring_enter"],
            bypasses_blocked=["socket", "connect"],
            severity="HIGH",
        )
        s = cf.summary
        assert "io_uring_setup" in s
        assert "io_uring_enter" in s
        assert "socket" in s
        assert "connect" in s

    def test_summary_no_bypasses_blocked(self):
        cf = ComboFinding(
            id="COMBO-test",
            name="test combo",
            description="test",
            triggered_by=["io_uring_setup"],
            bypasses_blocked=[],
            severity="LOW",
        )
        assert "none currently blocked" in cf.summary


# ---------------------------------------------------------------------------
# Integration: score_profile() includes combo_findings
# ---------------------------------------------------------------------------

class TestScoreProfileCombos:
    def test_score_profile_has_combo_findings_field(self):
        profile = _profile(rules=[_allow("io_uring_setup", "io_uring_enter")])
        result = score_profile(profile)
        assert hasattr(result, "combo_findings")
        assert isinstance(result.combo_findings, list)

    def test_combo_findings_populated_for_iouring_profile(self):
        profile = _profile(rules=[_allow("io_uring_setup", "io_uring_enter")])
        result = score_profile(profile)
        assert len(result.combo_findings) > 0
        ids = [f.id for f in result.combo_findings]
        assert "COMBO-io-uring-network-bypass" in ids

    def test_combo_findings_empty_for_clean_profile(self):
        """Profile with no dangerous or io_uring syscalls — no combos."""
        profile = _profile(rules=[_allow("read", "write", "exit")])
        result = score_profile(profile)
        assert result.combo_findings == []

    def test_combo_warnings_appear_in_warnings_list(self):
        """Combo findings are surfaced as warnings for CLI visibility."""
        profile = _profile(rules=[_allow("io_uring_setup", "io_uring_enter")])
        result = score_profile(profile)
        combo_warnings = [w for w in result.warnings if w.startswith("COMBO")]
        assert len(combo_warnings) > 0
        assert any("io_uring network bypass" in w for w in combo_warnings)

    def test_score_not_inflated_by_iouring_bypass(self):
        """Profile blocking network but allowing io_uring scores < one blocking both."""
        # Profile A: blocks network AND io_uring
        profile_a = _profile(rules=[
            _block("io_uring_setup", "io_uring_enter",
                   "io_uring_register",
                   "socket", "connect"),
        ])
        # Profile B: blocks network but allows io_uring (bypasses the block)
        profile_b = _profile(rules=[
            _allow("io_uring_setup", "io_uring_enter"),
            _block("socket", "connect"),
        ])
        result_a = score_profile(profile_a)
        result_b = score_profile(profile_b)
        # B should score lower because io_uring is Tier 2 (deduction ~4.5)
        assert result_a.score > result_b.score

    def test_all_iouring_combo_ids_present(self):
        """All 8 io_uring combo rules should fire when io_uring is allowed
        and the profile uses defaultAction=SCMP_ACT_ERRNO (blocks everything else)."""
        profile = _profile(rules=[_allow("io_uring_setup", "io_uring_enter")])
        result = score_profile(profile)
        ids = {f.id for f in result.combo_findings}
        expected = {
            "COMBO-io-uring-network-bypass",
            "COMBO-io-uring-file-io-bypass",
            "COMBO-io-uring-filesystem-bypass",
            "COMBO-io-uring-xattr-bypass",
            "COMBO-io-uring-poll-bypass",
            "COMBO-io-uring-splice-bypass",
            "COMBO-io-uring-process-bypass",
            "COMBO-io-uring-ioctl-bypass",
        }
        assert expected == ids
