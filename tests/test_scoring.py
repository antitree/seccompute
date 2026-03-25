"""Behavioral tests for the scoring engine per SPEC.md."""
import pytest
from seccompute import score_profile, ScoringResult
from tests.conftest import make_profile, allow_rule, block_rule


# ---------------------------------------------------------------------------
# Public API contract
# ---------------------------------------------------------------------------

class TestPublicAPI:
    def test_import_symbols(self):
        from seccompute import score_profile, ScoringResult
        assert callable(score_profile)
        assert ScoringResult is not None

    def test_returns_scoring_result(self):
        result = score_profile(make_profile())
        assert isinstance(result, ScoringResult)

    def test_result_has_all_fields(self):
        result = score_profile(make_profile())
        assert isinstance(result.score, int)
        assert 0 <= result.score <= 100
        assert result.grade in ("A", "B", "C", "D", "F")
        assert isinstance(result.forced_failure, bool)
        assert isinstance(result.forced_failure_reasons, list)
        assert isinstance(result.annotation_overrides, list)
        assert isinstance(result.scoring_mode, str)
        assert isinstance(result.tier_summary, dict)
        assert isinstance(result.tier_findings, list)
        assert isinstance(result.combo_findings, list)
        assert isinstance(result.conditional_findings, list)
        assert isinstance(result.warnings, list)
        assert isinstance(result.metadata, dict)

    def test_to_json_returns_valid_json(self):
        import json
        result = score_profile(make_profile())
        data = json.loads(result.to_json())
        assert data["schema_version"] == "1.0"
        assert "score" in data
        assert "grade" in data

    def test_to_dict_matches_to_json(self):
        import json
        result = score_profile(make_profile())
        assert json.loads(result.to_json()) == result.to_dict()


# ---------------------------------------------------------------------------
# Score boundaries
# ---------------------------------------------------------------------------

class TestScoreBoundaries:
    def test_deny_all_scores_100(self):
        """ERRNO default with no allow rules = everything blocked = 100."""
        result = score_profile(make_profile("SCMP_ACT_ERRNO"))
        assert result.score == 100

    def test_allow_all_scores_0(self):
        """ALLOW default = everything allowed = 0."""
        result = score_profile(make_profile("SCMP_ACT_ALLOW"))
        assert result.score == 0

    def test_score_clamped_0_100(self):
        for default in ["SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO"]:
            result = score_profile(make_profile(default))
            assert 0 <= result.score <= 100


# ---------------------------------------------------------------------------
# Tier budget deductions
# ---------------------------------------------------------------------------

class TestTierBudgets:
    def test_all_t1_allowed_deducts_t1_budget(self):
        """Allowing all T1 unconditionally deducts exactly T1 budget (85)."""
        from seccompute.tiers import build_tiers, TIER_BUDGETS
        from seccompute.rules import load_all_rules
        rules = load_all_rules()
        tiers = build_tiers(rules["syscalls"])
        t1 = tiers[1]

        result = score_profile(make_profile(rules=[allow_rule(*t1)]))
        assert result.score == round(100 - TIER_BUDGETS[1])

    def test_single_t1_deduction(self):
        """One T1 syscall deducts budget/count."""
        from seccompute.tiers import build_tiers, TIER_BUDGETS
        from seccompute.rules import load_all_rules
        rules = load_all_rules()
        tiers = build_tiers(rules["syscalls"])
        t1 = tiers[1]
        expected = round(100 - TIER_BUDGETS[1] / len(t1))

        result = score_profile(make_profile(rules=[allow_rule("bpf")]))
        assert result.score == expected


# ---------------------------------------------------------------------------
# Conditional scoring
# ---------------------------------------------------------------------------

class TestConditionalScoring:
    def test_conditional_between_blocked_and_allowed(self):
        """Cap-gated allow with cap granted scores between fully blocked and fully allowed.
        (arg-filter conditionals still use 0.5x multiplier)"""
        r_blocked = score_profile(make_profile())
        r_allowed = score_profile(make_profile(rules=[allow_rule("bpf")]))
        r_cond = score_profile(make_profile(rules=[
            allow_rule("bpf", includes={"caps": ["CAP_BPF"]}),
        ]), granted_caps=frozenset({"CAP_BPF"}))
        # With cap granted, cap-gated == unconditional allow, so scores equal
        assert r_allowed.score == r_cond.score
        assert r_cond.score < r_blocked.score

    def test_cap_gated_no_caps_context_scores_same_as_blocked(self):
        """Cap-gated allow with no caps context is ignored — scores same as no rule."""
        r_no_rule = score_profile(make_profile())
        r_cap_gated = score_profile(make_profile(rules=[
            allow_rule("bpf", includes={"caps": ["CAP_BPF"]}),
        ]))
        assert r_cap_gated.score == r_no_rule.score

    def test_t1_conditional_uses_075_multiplier(self):
        """T1 cap-gated with cap granted uses 1.0x multiplier (full weight)."""
        from seccompute.tiers import build_tiers, TIER_BUDGETS
        from seccompute.rules import load_all_rules
        rules = load_all_rules()
        tiers = build_tiers(rules["syscalls"])
        t1 = tiers[1]
        weight = TIER_BUDGETS[1] / len(t1)
        expected = round(100 - weight * 1.0)

        result = score_profile(make_profile(rules=[
            allow_rule("bpf", includes={"caps": ["CAP_BPF"]}),
        ]), granted_caps=frozenset({"CAP_BPF"}))
        assert result.score == expected


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_input_same_output(self):
        p = make_profile(rules=[allow_rule("bpf", "mount")])
        results = [score_profile(p) for _ in range(5)]
        for r in results[1:]:
            assert r.score == results[0].score


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

class TestMetadata:
    def test_metadata_fields(self):
        result = score_profile(make_profile())
        assert "engine_version" in result.metadata
        assert "arch" in result.metadata
        assert "schema_version" in result.metadata
        assert result.metadata["schema_version"] == "1.0"

    def test_arch_passthrough(self):
        result = score_profile(make_profile(), arch="SCMP_ARCH_AARCH64")
        assert result.metadata["arch"] == "SCMP_ARCH_AARCH64"
