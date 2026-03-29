"""Tests for the public get_dangerous_syscalls() API and --dump-rules CLI flag.

Verifies Phase 1 of SYSCALL_GENERATION_V2_SPEC.md:
- get_dangerous_syscalls() returns correct shape
- Version matches importlib.metadata.version("seccompute")
- All 50 dangerous syscalls are present
- Each syscall entry has required fields with valid tier values
- Combos and conditionals have expected fields
- --dump-rules CLI flag outputs valid JSON matching the API
"""
from __future__ import annotations

import importlib.metadata
import json
import subprocess
import sys

import pytest


class TestGetDangerousSyscalls:
    """Test the public get_dangerous_syscalls() function."""

    def test_returns_dict_with_required_keys(self):
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        assert isinstance(result, dict)
        assert "version" in result
        assert "syscalls" in result
        assert "combos" in result
        assert "conditionals" in result

    def test_version_matches_package_version(self):
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        expected = importlib.metadata.version("seccompute")
        assert result["version"] == expected

    def test_syscalls_contains_all_50(self):
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        assert len(result["syscalls"]) == 50, (
            f"Expected 50 dangerous syscalls, got {len(result['syscalls'])}"
        )

    def test_syscall_entries_have_required_fields(self):
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        for name, entry in result["syscalls"].items():
            assert "tier" in entry, f"{name} missing 'tier'"
            assert "category" in entry, f"{name} missing 'category'"
            assert "description" in entry, f"{name} missing 'description'"

    def test_syscall_tier_values_are_valid(self):
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        for name, entry in result["syscalls"].items():
            assert entry["tier"] in (1, 2, 3), (
                f"{name} has invalid tier: {entry['tier']}"
            )

    def test_syscall_entries_have_threats(self):
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        for name, entry in result["syscalls"].items():
            assert "threats" in entry, f"{name} missing 'threats'"
            assert isinstance(entry["threats"], list), (
                f"{name} threats is not a list"
            )

    def test_known_tier1_syscalls_present(self):
        """Spot-check that critical tier 1 syscalls are included."""
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        tier1_expected = {"bpf", "ptrace", "kexec_load", "init_module", "finit_module"}
        for sc in tier1_expected:
            assert sc in result["syscalls"], f"Tier 1 syscall '{sc}' missing"
            assert result["syscalls"][sc]["tier"] == 1

    def test_combos_is_list_with_expected_fields(self):
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        assert isinstance(result["combos"], list)
        assert len(result["combos"]) > 0, "Expected at least one combo rule"
        for combo in result["combos"]:
            assert "id" in combo, f"Combo missing 'id'"
            assert "name" in combo, f"Combo missing 'name'"
            assert "syscalls" in combo, f"Combo {combo.get('id', '?')} missing 'syscalls'"
            assert "severity" in combo, f"Combo {combo.get('id', '?')} missing 'severity'"
            assert isinstance(combo["syscalls"], list)
            assert len(combo["syscalls"]) > 0

    def test_conditionals_is_list_with_expected_fields(self):
        from seccompute import get_dangerous_syscalls

        result = get_dangerous_syscalls()
        assert isinstance(result["conditionals"], list)
        assert len(result["conditionals"]) > 0, "Expected at least one conditional rule"
        for cond in result["conditionals"]:
            assert "syscall" in cond, f"Conditional missing 'syscall'"
            assert "condition" in cond, f"Conditional missing 'condition'"
            assert "description" in cond, f"Conditional missing 'description'"

    def test_in_all_exports(self):
        """get_dangerous_syscalls must be in __all__."""
        import seccompute

        assert "get_dangerous_syscalls" in seccompute.__all__


class TestDumpRulesCLI:
    """Test the --dump-rules CLI flag."""

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "seccompute"] + args,
            capture_output=True,
            text=True,
        )

    def test_dump_rules_outputs_valid_json(self):
        r = self._run(["--dump-rules"])
        assert r.returncode == 0, f"stderr: {r.stderr}"
        data = json.loads(r.stdout)
        assert isinstance(data, dict)

    def test_dump_rules_has_required_keys(self):
        r = self._run(["--dump-rules"])
        data = json.loads(r.stdout)
        assert "version" in data
        assert "syscalls" in data
        assert "combos" in data
        assert "conditionals" in data

    def test_dump_rules_matches_api(self):
        """CLI --dump-rules output must match get_dangerous_syscalls() exactly."""
        from seccompute import get_dangerous_syscalls

        r = self._run(["--dump-rules"])
        cli_data = json.loads(r.stdout)
        api_data = get_dangerous_syscalls()
        assert cli_data == api_data

    def test_dump_rules_ignores_profile_arg(self):
        """--dump-rules should work even without a profile argument."""
        r = self._run(["--dump-rules"])
        assert r.returncode == 0

    def test_dump_rules_exits_before_scoring(self):
        """--dump-rules should not require stdin or a profile file."""
        r = self._run(["--dump-rules"])
        assert r.returncode == 0
        assert "Error" not in r.stderr
