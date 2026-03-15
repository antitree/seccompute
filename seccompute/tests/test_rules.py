"""Tests for rules.py: YAML loading, schema validation, tier completeness."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.rules import get_all_rules, get_rule, get_tier
from seccompute.weights_v2 import ALL_DANGEROUS_V2, TIER1, TIER2, TIER3


# ---------------------------------------------------------------------------
# YAML loads without error
# ---------------------------------------------------------------------------

def test_yaml_loads_successfully():
    """syscall_rules.yaml must load and return a non-empty dict."""
    rules = get_all_rules()
    assert isinstance(rules, dict)
    assert len(rules) > 0


# ---------------------------------------------------------------------------
# All tier syscalls present
# ---------------------------------------------------------------------------

def test_all_tier1_syscalls_present():
    """Every syscall in weights_v2.TIER1 must be present in the YAML."""
    rules = get_all_rules()
    for sc in TIER1:
        assert sc in rules, f"Tier 1 syscall '{sc}' missing from YAML rules"


def test_all_tier2_syscalls_present():
    """Every syscall in weights_v2.TIER2 must be present in the YAML."""
    rules = get_all_rules()
    for sc in TIER2:
        assert sc in rules, f"Tier 2 syscall '{sc}' missing from YAML rules"


def test_all_tier3_syscalls_present():
    """Every syscall in weights_v2.TIER3 must be present in the YAML."""
    rules = get_all_rules()
    for sc in TIER3:
        assert sc in rules, f"Tier 3 syscall '{sc}' missing from YAML rules"


def test_all_dangerous_v2_present():
    """Every syscall in ALL_DANGEROUS_V2 must be in the YAML."""
    rules = get_all_rules()
    for sc in ALL_DANGEROUS_V2:
        assert sc in rules, f"Dangerous syscall '{sc}' missing from YAML rules"


# ---------------------------------------------------------------------------
# No duplicates (YAML keys are unique by spec, but verify tier consistency)
# ---------------------------------------------------------------------------

def test_no_tier_conflicts():
    """No syscall should appear in multiple tier lists in weights_v2.py."""
    overlap_12 = set(TIER1) & set(TIER2)
    overlap_13 = set(TIER1) & set(TIER3)
    overlap_23 = set(TIER2) & set(TIER3)
    assert not overlap_12, f"Overlap T1/T2: {overlap_12}"
    assert not overlap_13, f"Overlap T1/T3: {overlap_13}"
    assert not overlap_23, f"Overlap T2/T3: {overlap_23}"


# ---------------------------------------------------------------------------
# Schema validation per entry
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {"tier", "category", "description", "threats", "last_reviewed"}
VALID_CATEGORIES = {
    "kernel_module", "process_inspection", "namespace_escape",
    "filesystem_escape", "io_subsystem", "kernel_keyring",
    "system_control", "memory_management", "device_access",
}


@pytest.mark.parametrize("syscall", sorted(ALL_DANGEROUS_V2))
def test_rule_schema_valid(syscall):
    """Each rule must have all required fields with correct types."""
    rule = get_rule(syscall)
    assert rule is not None, f"No rule found for {syscall}"

    for field in REQUIRED_FIELDS:
        assert field in rule, f"Rule for '{syscall}' missing field '{field}'"

    assert rule["tier"] in (1, 2, 3), f"Invalid tier {rule['tier']} for {syscall}"
    assert rule["category"] in VALID_CATEGORIES, f"Invalid category '{rule['category']}' for {syscall}"
    assert isinstance(rule["description"], str) and len(rule["description"]) > 10
    assert isinstance(rule["threats"], list) and len(rule["threats"]) > 0
    assert isinstance(rule["last_reviewed"], str)


@pytest.mark.parametrize("syscall", sorted(ALL_DANGEROUS_V2))
def test_threat_entries_valid(syscall):
    """Each threat entry must have id and description."""
    rule = get_rule(syscall)
    for threat in rule["threats"]:
        assert "id" in threat, f"Threat missing 'id' in {syscall}"
        assert "description" in threat, f"Threat missing 'description' in {syscall}"
        assert "date_added" in threat, f"Threat missing 'date_added' in {syscall}"


# ---------------------------------------------------------------------------
# Tier values match weights_v2.py
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("syscall", TIER1)
def test_tier1_yaml_matches(syscall):
    """YAML tier must match weights_v2.py TIER1 assignment."""
    assert get_tier(syscall) == 1


@pytest.mark.parametrize("syscall", TIER2)
def test_tier2_yaml_matches(syscall):
    """YAML tier must match weights_v2.py TIER2 assignment."""
    assert get_tier(syscall) == 2


@pytest.mark.parametrize("syscall", TIER3)
def test_tier3_yaml_matches(syscall):
    """YAML tier must match weights_v2.py TIER3 assignment."""
    assert get_tier(syscall) == 3


# ---------------------------------------------------------------------------
# get_tier returns 0 for unknown syscalls
# ---------------------------------------------------------------------------

def test_unknown_syscall_tier_is_zero():
    """Unknown syscalls should return tier 0 from get_tier."""
    assert get_tier("totally_fake_syscall_xyz") == 0
