"""Intent block handler for x-seccompute embedded metadata."""
from __future__ import annotations

import json
import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class SyscallIntent:
    justification: str
    confined: bool = False


@dataclass
class IntentBlock:
    description: str = ""
    syscalls: dict[str, SyscallIntent] = field(default_factory=dict)


def load_intent(profile: dict) -> IntentBlock | None:
    """Extract intent block from a profile dict. Returns None if not present."""
    raw = profile.get("x-seccompute", {}).get("intent")
    if not raw:
        return None
    syscalls = {}
    for name, data in raw.get("syscalls", {}).items():
        if isinstance(data, dict):
            syscalls[name] = SyscallIntent(
                justification=data.get("justification", ""),
                confined=bool(data.get("confined", False)),
            )
    return IntentBlock(
        description=raw.get("description", ""),
        syscalls=syscalls,
    )


def load_intent_from_file(profile_path: Path) -> IntentBlock | None:
    """Load intent block from a profile file."""
    try:
        with open(profile_path, encoding="utf-8") as f:
            profile = json.load(f)
        return load_intent(profile)
    except (OSError, json.JSONDecodeError, KeyError):
        return None


def embed_scores(profile: dict, risk: int, correctness: int | None, engine_version: str) -> dict:
    """Return a new profile dict with scores written into x-seccompute.scores. Does not mutate original."""
    result = copy.deepcopy(profile)
    block = result.setdefault("x-seccompute", {})
    block["scores"] = {
        "risk": risk,
        "correctness": correctness,
        "generated": datetime.now(timezone.utc).isoformat(),
        "engine_version": engine_version,
    }
    return result


def save_profile_with_scores(profile_path: Path, profile: dict, risk: int, correctness: int | None, engine_version: str) -> None:
    """Write profile back to file with scores embedded in x-seccompute block."""
    annotated = embed_scores(profile, risk, correctness, engine_version)
    with open(profile_path, "w", encoding="utf-8") as f:
        json.dump(annotated, f, indent=2)
        f.write("\n")
