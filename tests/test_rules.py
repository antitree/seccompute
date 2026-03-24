"""Behavioral tests for rule loading and validation per SPEC.md."""
import pytest
from seccompute.rules import load_all_rules, clear_cache


class TestRuleLoading:
    def setup_method(self):
        clear_cache()

    def test_loads_all_rule_types(self):
        rules = load_all_rules()
        assert "syscalls" in rules
        assert "combos" in rules
        assert "conditionals" in rules

    def test_syscall_rules_have_required_fields(self):
        rules = load_all_rules()
        for name, entry in rules["syscalls"].items():
            assert "tier" in entry, f"{name} missing tier"
            assert "category" in entry, f"{name} missing category"
            assert "description" in entry, f"{name} missing description"
            assert isinstance(entry["tier"], int)
            assert entry["tier"] in (1, 2, 3)

    def test_combo_rules_have_required_fields(self):
        rules = load_all_rules()
        for combo in rules["combos"]:
            assert "id" in combo
            assert "syscalls" in combo
            assert len(combo["syscalls"]) > 0
            assert "trigger" in combo
            assert "severity" in combo

    def test_conditionals_is_list(self):
        rules = load_all_rules()
        assert isinstance(rules["conditionals"], list)

    def test_caching(self):
        r1 = load_all_rules()
        r2 = load_all_rules()
        assert r1 is r2


class TestRuleValidation:
    def test_invalid_syscall_rules(self, tmp_path):
        (tmp_path / "syscall_rules.yaml").write_text("not_a_dict")
        with pytest.raises(ValueError, match="expected dict"):
            load_all_rules(str(tmp_path))

    def test_invalid_combo_rules(self, tmp_path):
        # Valid syscall rules but invalid combo rules
        (tmp_path / "syscall_rules.yaml").write_text(
            "bpf:\n  tier: 1\n  category: test\n  description: test\n"
        )
        (tmp_path / "combo_rules.yaml").write_text("not_valid: true")
        with pytest.raises(ValueError, match="combos"):
            clear_cache()
            load_all_rules(str(tmp_path))


class TestRulesDir:
    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError, match="traversal"):
            load_all_rules("/etc/../etc/passwd")
