"""Tests for correctness scoring and intent block handling."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.intent import (
    IntentBlock,
    SyscallIntent,
    embed_scores,
    load_intent,
    load_intent_from_file,
    save_profile_with_scores,
)
from seccompute.correctness import CorrectnessDetail, compute_correctness
from seccompute.scoring import ScoringResult, score_profile
from seccompute.__main__ import _serialize_result, _format_text
from seccompute.weights_v2 import TIER1, TIER2, TIER1_BUDGET


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _profile(default_action="SCMP_ACT_ERRNO", rules=None, intent=None):
    p = {"defaultAction": default_action, "syscalls": rules or []}
    if intent is not None:
        p["x-seccompute"] = {"intent": intent}
    return p


def _rule(names, action):
    return {"names": names, "action": action}


def _intent_block(description="", syscalls=None):
    return {
        "description": description,
        "syscalls": syscalls or {},
    }


# ---------------------------------------------------------------------------
# IntentBlock loading
# ---------------------------------------------------------------------------

class TestLoadIntent:
    def test_load_intent_from_profile_dict(self):
        profile = _profile(intent=_intent_block(
            description="test app",
            syscalls={"bpf": {"justification": "needed for ebpf", "confined": True}},
        ))
        ib = load_intent(profile)
        assert ib is not None
        assert ib.description == "test app"
        assert "bpf" in ib.syscalls
        assert ib.syscalls["bpf"].justification == "needed for ebpf"
        assert ib.syscalls["bpf"].confined is True

    def test_load_intent_missing_returns_none(self):
        profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        assert load_intent(profile) is None

    def test_load_intent_empty_block_returns_none(self):
        profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [], "x-seccompute": {}}
        assert load_intent(profile) is None

    def test_load_intent_confined_flag_true(self):
        profile = _profile(intent=_intent_block(
            syscalls={"mount": {"justification": "fuse", "confined": True}},
        ))
        ib = load_intent(profile)
        assert ib.syscalls["mount"].confined is True

    def test_load_intent_confined_flag_false(self):
        profile = _profile(intent=_intent_block(
            syscalls={"mount": {"justification": "fuse", "confined": False}},
        ))
        ib = load_intent(profile)
        assert ib.syscalls["mount"].confined is False

    def test_load_intent_confined_default_false(self):
        profile = _profile(intent=_intent_block(
            syscalls={"mount": {"justification": "fuse"}},
        ))
        ib = load_intent(profile)
        assert ib.syscalls["mount"].confined is False

    def test_load_intent_description(self):
        profile = _profile(intent=_intent_block(description="nginx reverse proxy"))
        ib = load_intent(profile)
        assert ib.description == "nginx reverse proxy"


# ---------------------------------------------------------------------------
# Correctness score computation
# ---------------------------------------------------------------------------

class TestComputeCorrectness:
    def _make_sd(self, name, tier, state, weight):
        """Create a mock SyscallScore-like object."""
        from seccompute.scoring import SyscallScore
        return SyscallScore(
            name=name, tier=tier, state=state,
            weight=weight, multiplier=1.0, deduction=weight,
        )

    def test_unjustified_allowed_gets_full_penalty(self):
        sd = self._make_sd("bpf", 1, "allowed", 6.67)
        intent = IntentBlock(syscalls={})
        score, details = compute_correctness([sd], intent)
        d = details[0]
        assert d.multiplier == 1.0
        assert abs(d.deduction - 6.67) < 0.01

    def test_justified_confined_gets_zero_penalty(self):
        sd = self._make_sd("bpf", 1, "allowed", 6.67)
        intent = IntentBlock(syscalls={
            "bpf": SyscallIntent(justification="ebpf tracing", confined=True),
        })
        score, details = compute_correctness([sd], intent)
        d = details[0]
        assert d.multiplier == 0.0
        assert d.deduction == 0.0

    def test_justified_unconfined_gets_partial_penalty(self):
        sd = self._make_sd("bpf", 1, "allowed", 6.67)
        intent = IntentBlock(syscalls={
            "bpf": SyscallIntent(justification="ebpf tracing", confined=False),
        })
        score, details = compute_correctness([sd], intent)
        d = details[0]
        assert d.multiplier == 0.3
        assert abs(d.deduction - 6.67 * 0.3) < 0.01

    def test_blocked_syscall_zero_deduction(self):
        sd = self._make_sd("bpf", 1, "blocked", 6.67)
        intent = IntentBlock(syscalls={})
        score, details = compute_correctness([sd], intent)
        d = details[0]
        assert d.deduction == 0.0

    def test_correctness_100_all_justified_confined(self):
        sds = [self._make_sd("bpf", 1, "allowed", 6.67),
               self._make_sd("mount", 2, "allowed", 3.0)]
        intent = IntentBlock(syscalls={
            "bpf": SyscallIntent(justification="tracing", confined=True),
            "mount": SyscallIntent(justification="fuse", confined=True),
        })
        score, _ = compute_correctness(sds, intent)
        assert score == 100

    def test_correctness_same_as_risk_when_no_justifications(self):
        sd = self._make_sd("bpf", 1, "allowed", 6.67)
        intent = IntentBlock(syscalls={})  # no entries
        score, _ = compute_correctness([sd], intent)
        # deduction = 6.67 * 1.0 = 6.67, score = 100 - 6.67 = 93
        expected = max(0, min(100, round(100.0 - 6.67)))
        assert score == expected


# ---------------------------------------------------------------------------
# score_profile() integration
# ---------------------------------------------------------------------------

class TestScoreProfileIntegration:
    def test_no_intent_correctness_is_none(self):
        p = _profile()
        result = score_profile(p)
        assert result.correctness_score is None

    def test_intent_in_profile_triggers_correctness(self):
        p = _profile(
            rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")],
            intent=_intent_block(
                description="test",
                syscalls={"bpf": {"justification": "tracing", "confined": True}},
            ),
        )
        result = score_profile(p)
        assert isinstance(result.correctness_score, int)

    def test_explicit_intent_param_triggers_correctness(self):
        p = _profile(rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")])
        intent = IntentBlock(syscalls={
            "bpf": SyscallIntent(justification="tracing", confined=True),
        })
        result = score_profile(p, intent=intent)
        assert isinstance(result.correctness_score, int)

    def test_risk_score_unchanged_by_intent(self):
        p_no_intent = _profile(rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")])
        r1 = score_profile(p_no_intent)

        p_with_intent = _profile(
            rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")],
            intent=_intent_block(
                syscalls={"bpf": {"justification": "tracing", "confined": True}},
            ),
        )
        r2 = score_profile(p_with_intent)
        assert r1.score == r2.score

    def test_correctness_better_than_or_equal_risk(self):
        """When intent provides credit, correctness >= risk score."""
        p = _profile(
            rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")],
            intent=_intent_block(
                syscalls={"bpf": {"justification": "tracing", "confined": True}},
            ),
        )
        result = score_profile(p)
        assert result.correctness_score >= result.score

    def test_correctness_details_populated(self):
        p = _profile(
            rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")],
            intent=_intent_block(
                syscalls={"bpf": {"justification": "tracing", "confined": True}},
            ),
        )
        result = score_profile(p)
        assert len(result.correctness_details) > 0
        names = [cd.name for cd in result.correctness_details]
        assert "bpf" in names


# ---------------------------------------------------------------------------
# embed_scores / save roundtrip
# ---------------------------------------------------------------------------

class TestEmbedScores:
    def test_embed_scores_adds_block(self):
        profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        result = embed_scores(profile, risk=85, correctness=92, engine_version="2.0.0")
        assert result["x-seccompute"]["scores"]["risk"] == 85
        assert result["x-seccompute"]["scores"]["correctness"] == 92

    def test_embed_scores_does_not_mutate_original(self):
        profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        embed_scores(profile, risk=85, correctness=92, engine_version="2.0.0")
        assert "x-seccompute" not in profile

    def test_save_and_reload_roundtrip(self, tmp_path):
        profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        path = tmp_path / "test.json"
        save_profile_with_scores(path, profile, risk=85, correctness=92, engine_version="2.0.0")

        with open(path) as f:
            loaded = json.load(f)
        assert loaded["x-seccompute"]["scores"]["risk"] == 85
        assert loaded["x-seccompute"]["scores"]["correctness"] == 92

    def test_save_correctness_none(self, tmp_path):
        profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
        path = tmp_path / "test.json"
        save_profile_with_scores(path, profile, risk=100, correctness=None, engine_version="2.0.0")

        with open(path) as f:
            loaded = json.load(f)
        assert loaded["x-seccompute"]["scores"]["correctness"] is None


# ---------------------------------------------------------------------------
# JSON output format
# ---------------------------------------------------------------------------

class TestJsonOutput:
    def test_json_output_has_risk_score_key(self):
        p = _profile()
        result = score_profile(p)
        output = _serialize_result(result)
        assert "risk_score" in output
        assert "score" not in output

    def test_json_output_correctness_null_no_intent(self):
        p = _profile()
        result = score_profile(p)
        output = _serialize_result(result)
        assert output["correctness"] is None

    def test_json_output_correctness_present_with_intent(self):
        p = _profile(
            rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")],
            intent=_intent_block(
                syscalls={"bpf": {"justification": "tracing", "confined": True}},
            ),
        )
        result = score_profile(p)
        output = _serialize_result(result)
        assert output["correctness"] is not None
        assert "score" in output["correctness"]


# ---------------------------------------------------------------------------
# Text output format
# ---------------------------------------------------------------------------

class TestTextOutput:
    def test_text_shows_both_scores_with_intent(self):
        p = _profile(
            rules=[_rule(["bpf"], "SCMP_ACT_ALLOW")],
            intent=_intent_block(
                syscalls={"bpf": {"justification": "tracing", "confined": True}},
            ),
        )
        result = score_profile(p)
        text = _format_text(result)
        assert "Risk Score:" in text
        assert "Correctness Score:" in text

    def test_text_shows_na_correctness_without_intent(self):
        p = _profile()
        result = score_profile(p)
        text = _format_text(result)
        # Without intent, correctness line is omitted entirely
        assert "Correctness" not in text
