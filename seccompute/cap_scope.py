"""Capability-to-syscall scope mapping for elevated scoring mode."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml

_CAP_SCOPE_PATH = Path(__file__).parent / "cap_scope.yaml"
_cached: dict[str, Any] | None = None


def _load() -> dict[str, Any]:
    global _cached
    if _cached is None:
        with open(_CAP_SCOPE_PATH, encoding="utf-8") as f:
            _cached = yaml.safe_load(f).get("cap_scope", {})
    return _cached


def get_scope_for_caps(caps: list[str]) -> tuple[set[str], set[str]]:
    """Return (primary_syscalls, related_syscalls) justified by the given caps."""
    scope = _load()
    primary: set[str] = set()
    related: set[str] = set()
    for cap in caps:
        entry = scope.get(cap, {})
        primary.update(entry.get("primary", []))
        related.update(entry.get("related", []))
    # related only counts if not already primary
    related -= primary
    return primary, related
