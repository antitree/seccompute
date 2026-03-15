"""Tests for conditionals.py: capability gates, argument filters, kernel versions.

CONDITIONAL SCORING PROPOSALS (for antitree to choose):
=======================================================

PROPOSAL A: Binary Conditional (current implementation)
  - Any condition on an allow rule -> 0.5x weight
  - Any deny with cap exclude -> 0.5x weight
  - Simple, predictable, easy to reason about
  - Example: Docker's "bpf with CAP_BPF" -> 0.5x of bpf weight
  - Example: Docker's "clone with MASKED_EQ filter" -> 0.5x of clone weight

PROPOSAL B: Graduated Conditional Scoring
  - Capability gate -> 0.5x (requires explicit cap grant)
  - Meaningful arg filter -> 0.6x (restricts some usage but not all)
  - Trivial arg filter -> 0.9x (barely restricts, almost same as allowed)
  - Kernel version gate -> 0.8x (assume most permissive path)
  - Example: Docker's "clone with MASKED_EQ on flags" -> 0.6x (meaningful)
  - Example: Docker's "personality with EQ 0" -> 0.9x (trivial for dangerous)
  - Example: containerd's "clone3 ENOSYS without CAP_SYS_ADMIN" -> 0.5x

PROPOSAL C: Condition-Type Weighted Scoring
  - CAP_SYS_ADMIN gate -> 0.3x (very restricted, rarely granted to containers)
  - Other capability gate -> 0.5x (restricted but more commonly granted)
  - Arg filter with MASKED_EQ -> 0.5x (blocks specific flag combinations)
  - Arg filter with EQ/NE -> 0.7x (allows specific values, easy to satisfy)
  - Kernel version gate -> 1.0x (no reduction - attacker controls perception)
  - Deny with cap exclude -> 0.5x (can be bypassed by granting the cap)
  - Multiple conditions -> use the most permissive (lowest) multiplier
  - Example: Docker's big CAP_SYS_ADMIN block (bpf,clone,mount...) -> 0.3x each
  - Example: Podman's unconditional allow for ptrace/process_vm_* -> 1.0x
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.conditionals import analyze_conditionals, ConditionalNote
from seccompute.scoring import score_profile
from seccompute.weights_v2 import TIER1_BUDGET, TIER1, TIER2_BUDGET, TIER2


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
# Capability-gated allow -> 0.5x weight
# ---------------------------------------------------------------------------

def test_cap_gated_allow_is_conditional():
    """ALLOW with includes.caps -> detected as capability-gated conditional."""
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["bpf"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_BPF"]})
    ])
    notes = analyze_conditionals(p)
    bpf_notes = [n for n in notes if n.syscall == "bpf"]
    assert len(bpf_notes) > 0
    assert bpf_notes[0].condition_type == "capability_gate"
    assert "CAP_BPF" in bpf_notes[0].details


def test_cap_gated_allow_reduces_score():
    """Capability-gated allow should score higher (better) than unconditional allow."""
    # Unconditional allow
    p_uncond = _profile("SCMP_ACT_ERRNO", [_rule(["bpf"], "SCMP_ACT_ALLOW")])
    r_uncond = score_profile(p_uncond)

    # Cap-gated allow
    p_cond = _profile("SCMP_ACT_ERRNO", [
        _rule(["bpf"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_BPF"]})
    ])
    r_cond = score_profile(p_cond)

    assert r_cond.score > r_uncond.score


# ---------------------------------------------------------------------------
# Argument-filtered allow -> 0.5x weight
# ---------------------------------------------------------------------------

def test_arg_filtered_allow_is_conditional():
    """ALLOW with args -> detected as argument-filtered conditional."""
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["clone"], "SCMP_ACT_ALLOW",
              args=[{"index": 0, "value": 2114060288, "op": "SCMP_CMP_MASKED_EQ"}])
    ])
    notes = analyze_conditionals(p)
    clone_notes = [n for n in notes if n.syscall == "clone"]
    assert len(clone_notes) > 0
    assert clone_notes[0].condition_type == "argument_filter"


def test_arg_filtered_allow_reduces_score():
    """Arg-filtered allow should score higher than unconditional allow.

    Uses mount (T2, weight=1.5) instead of clone (T3, weight=0.476) to ensure
    the difference is visible after rounding.
    """
    p_uncond = _profile("SCMP_ACT_ERRNO", [_rule(["mount"], "SCMP_ACT_ALLOW")])
    r_uncond = score_profile(p_uncond)

    p_cond = _profile("SCMP_ACT_ERRNO", [
        _rule(["mount"], "SCMP_ACT_ALLOW",
              args=[{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}])
    ])
    r_cond = score_profile(p_cond)

    assert r_cond.score > r_uncond.score


# ---------------------------------------------------------------------------
# Kernel version gates -> most permissive path
# ---------------------------------------------------------------------------

def test_min_kernel_allow_is_conditional():
    """ALLOW with includes.minKernel -> detected as kernel version gate."""
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["ptrace"], "SCMP_ACT_ALLOW", includes={"minKernel": "4.8"})
    ])
    notes = analyze_conditionals(p)
    ptrace_notes = [n for n in notes if n.syscall == "ptrace"]
    assert len(ptrace_notes) > 0
    assert ptrace_notes[0].condition_type == "kernel_version_gate"


def test_min_kernel_treated_as_conditional():
    """Kernel version gate should be treated as conditional (most permissive path).

    Docker allows ptrace with minKernel: 4.8. Since virtually all modern systems
    run >= 4.8, this is practically unconditional. But we score it as conditional
    (0.5x) per spec.
    """
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["ptrace"], "SCMP_ACT_ALLOW", includes={"minKernel": "4.8"})
    ])
    result = score_profile(p)

    full_deduction = TIER1_BUDGET / len(TIER1)
    half_deduction = full_deduction * 0.5
    expected = round(100 - half_deduction)
    assert result.score == expected


# ---------------------------------------------------------------------------
# Deny with capability exclusion -> conditional
# ---------------------------------------------------------------------------

def test_deny_with_cap_exclude_is_conditional():
    """ERRNO with excludes.caps -> conditional (cap grants bypass the block)."""
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["clone3"], "SCMP_ACT_ERRNO", excludes={"caps": ["CAP_SYS_ADMIN"]})
    ])
    notes = analyze_conditionals(p)
    clone3_notes = [n for n in notes if n.syscall == "clone3"]
    assert len(clone3_notes) > 0
    assert clone3_notes[0].condition_type == "deny_with_cap_exclude"


def test_deny_with_cap_exclude_scores_as_conditional():
    """Deny with cap exclude means the syscall is reachable with the cap.

    Docker's clone3: SCMP_ACT_ERRNO excludes CAP_SYS_ADMIN means clone3 is
    blocked UNLESS the process has CAP_SYS_ADMIN. Score as conditional.
    """
    p = _profile("SCMP_ACT_ERRNO", [
        _rule(["clone3"], "SCMP_ACT_ERRNO", excludes={"caps": ["CAP_SYS_ADMIN"]})
    ])
    result = score_profile(p)

    # clone3 is tier 3
    full_deduction = 10 / 21  # TIER3_BUDGET / len(TIER3)
    half_deduction = full_deduction * 0.5
    expected = round(100 - half_deduction)
    assert result.score == expected


# ---------------------------------------------------------------------------
# Multiple conditionals on same syscall -> most permissive
# ---------------------------------------------------------------------------

def test_multiple_conditionals_uses_most_permissive():
    """When a syscall has both a conditional allow and an unconditional allow,
    the unconditional allow wins (most permissive interpretation).

    Example from Docker: clone has both:
    1. ALLOW with args (MASKED_EQ) excludes CAP_SYS_ADMIN -> conditional
    2. ALLOW with includes CAP_SYS_ADMIN -> conditional

    Both are conditional, so clone stays conditional (0.5x).
    But if one were unconditional, it would be treated as fully allowed (1.0x).
    """
    rules = [
        _rule(["mount"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_SYS_ADMIN"]}),
        _rule(["mount"], "SCMP_ACT_ALLOW"),  # unconditional trumps
    ]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)

    # mount is tier 2, unconditional allow -> full deduction
    full_deduction = TIER2_BUDGET / len(TIER2)
    expected = round(100 - full_deduction)
    assert result.score == expected


def test_multiple_conditional_rules_stays_conditional():
    """When all rules for a syscall are conditional, it stays conditional."""
    rules = [
        _rule(["bpf"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_SYS_ADMIN"]}),
        _rule(["bpf"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_BPF"]}),
    ]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)

    full_deduction = TIER1_BUDGET / len(TIER1)
    half_deduction = full_deduction * 0.5
    expected = round(100 - half_deduction)
    assert result.score == expected


# ---------------------------------------------------------------------------
# Real-world conditional examples from Docker/containerd/Podman defaults
# ---------------------------------------------------------------------------

def test_docker_open_by_handle_at_cap_gated():
    """Docker: open_by_handle_at allowed with CAP_DAC_READ_SEARCH.

    This is a classic conditional: the Shocker exploit requires this cap.
    Without the cap, open_by_handle_at is blocked. Score as conditional.
    """
    rules = [
        _rule(["open_by_handle_at"], "SCMP_ACT_ALLOW",
              includes={"caps": ["CAP_DAC_READ_SEARCH"]})
    ]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)
    # Should score between blocked (100) and fully allowed
    full_deduction = TIER2_BUDGET / len(TIER2)
    half_deduction = full_deduction * 0.5
    expected = round(100 - half_deduction)
    assert result.score == expected


def test_containerd_bpf_dual_conditional():
    """Containerd: bpf has both CAP_SYS_ADMIN allow AND ERRNO excludes {CAP_SYS_ADMIN, CAP_BPF}.

    The include-caps ALLOW makes it conditional. The exclude-caps ERRNO also
    makes it conditional. Most permissive = conditional (0.5x).
    """
    rules = [
        _rule(["bpf"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_SYS_ADMIN"]}),
        _rule(["bpf"], "SCMP_ACT_ERRNO",
              excludes={"caps": ["CAP_SYS_ADMIN", "CAP_BPF"]}),
        _rule(["bpf"], "SCMP_ACT_ALLOW", includes={"caps": ["CAP_BPF"]}),
    ]
    p = _profile("SCMP_ACT_ERRNO", rules)
    result = score_profile(p)

    full_deduction = TIER1_BUDGET / len(TIER1)
    half_deduction = full_deduction * 0.5
    expected = round(100 - half_deduction)
    assert result.score == expected
