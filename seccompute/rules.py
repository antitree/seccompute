"""YAML-based rule loader and validator for seccompute.

Loads syscall tier rules, combo rules, and conditional rules from YAML files.
Supports user-supplied rule directory overrides via parameter or env var.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

_BUILTIN_RULES_DIR = Path(__file__).parent / "rules"

# Cache keyed by resolved rules_dir path string
_cache: dict[str, dict[str, Any]] = {}


def _resolve_rules_dir(rules_dir: str | None = None) -> Path:
    """Resolve the rules directory, checking parameter then env var then built-in."""
    if rules_dir is not None:
        p = Path(rules_dir)
        if ".." in p.parts:
            raise ValueError(f"Path traversal detected in rules_dir: {rules_dir}")
        return p
    env = os.environ.get("SECCOMPUTE_RULES_DIR")
    if env:
        p = Path(env)
        if ".." in p.parts:
            raise ValueError(f"Path traversal detected in SECCOMPUTE_RULES_DIR: {env}")
        return p
    return _BUILTIN_RULES_DIR


def _load_yaml(path: Path) -> Any:
    """Load a YAML file safely."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _validate_syscall_rules(data: dict[str, Any]) -> None:
    """Validate syscall_rules.yaml structure."""
    if not isinstance(data, dict):
        raise ValueError(f"syscall_rules.yaml: expected dict, got {type(data).__name__}")
    for name, entry in data.items():
        if not isinstance(entry, dict):
            raise ValueError(f"syscall_rules.yaml: entry '{name}' must be a dict")
        if "tier" not in entry or not isinstance(entry["tier"], int):
            raise ValueError(f"syscall_rules.yaml: entry '{name}' missing integer 'tier'")
        if "category" not in entry or not isinstance(entry["category"], str):
            raise ValueError(f"syscall_rules.yaml: entry '{name}' missing string 'category'")
        if "description" not in entry or not isinstance(entry["description"], str):
            raise ValueError(f"syscall_rules.yaml: entry '{name}' missing string 'description'")


def _validate_combo_rules(data: dict[str, Any]) -> None:
    """Validate combo_rules.yaml structure."""
    if not isinstance(data, dict) or "combos" not in data:
        raise ValueError("combo_rules.yaml: must have top-level 'combos' list")
    combos = data["combos"]
    if not isinstance(combos, list):
        raise ValueError("combo_rules.yaml: 'combos' must be a list")
    for i, entry in enumerate(combos):
        if not isinstance(entry, dict):
            raise ValueError(f"combo_rules.yaml: entry {i} must be a dict")
        for field in ("id", "trigger", "severity"):
            if field not in entry:
                raise ValueError(f"combo_rules.yaml: entry {i} missing '{field}'")
        syscalls = entry.get("syscalls", [])
        if not isinstance(syscalls, list) or len(syscalls) == 0:
            raise ValueError(f"combo_rules.yaml: entry {i} 'syscalls' must be non-empty list")


def _validate_conditional_rules(data: dict[str, Any]) -> None:
    """Validate conditional_rules.yaml structure."""
    if not isinstance(data, dict) or "conditionals" not in data:
        raise ValueError("conditional_rules.yaml: must have top-level 'conditionals' list")
    if not isinstance(data["conditionals"], list):
        raise ValueError("conditional_rules.yaml: 'conditionals' must be a list")


def load_all_rules(rules_dir: str | None = None) -> dict[str, Any]:
    """Load and cache all rule files from the given rules directory.

    Returns a dict with keys: 'syscalls', 'combos', 'conditionals'.
    """
    rdir = _resolve_rules_dir(rules_dir)
    cache_key = str(rdir)

    if cache_key in _cache:
        return _cache[cache_key]

    # Syscall rules: try override dir first, fall back to built-in
    syscall_path = rdir / "syscall_rules.yaml"
    if not syscall_path.exists():
        syscall_path = _BUILTIN_RULES_DIR / "syscall_rules.yaml"
    syscall_data = _load_yaml(syscall_path)
    _validate_syscall_rules(syscall_data)

    # Combo rules
    combo_path = rdir / "combo_rules.yaml"
    if not combo_path.exists():
        combo_path = _BUILTIN_RULES_DIR / "combo_rules.yaml"
    combo_data = _load_yaml(combo_path)
    _validate_combo_rules(combo_data)

    # Conditional rules
    cond_path = rdir / "conditional_rules.yaml"
    if not cond_path.exists():
        cond_path = _BUILTIN_RULES_DIR / "conditional_rules.yaml"
    cond_data = _load_yaml(cond_path)
    _validate_conditional_rules(cond_data)

    result = {
        "syscalls": syscall_data,
        "combos": combo_data["combos"],
        "conditionals": cond_data["conditionals"],
    }
    _cache[cache_key] = result
    return result


def clear_cache() -> None:
    """Clear the rules cache. Useful for testing."""
    _cache.clear()
