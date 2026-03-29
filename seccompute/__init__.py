"""Seccomp profile scoring engine.

Public API:
    from seccompute import score_profile, ScoringResult, get_dangerous_syscalls
    result = score_profile(profile_dict)
    print(result.score)       # 0-100
    print(result.to_json())   # stable JSON

    data = get_dangerous_syscalls()
    print(data["version"])    # package version
    print(data["syscalls"])   # full syscall rules dict
"""

from .model import ScoringResult
from .scoring import score_profile

__all__ = ["score_profile", "ScoringResult", "get_dangerous_syscalls"]


def get_dangerous_syscalls() -> dict:
    """Return the full dangerous syscall dataset.

    This is a stable public API. Internal rule format changes must not
    break this output shape.

    Returns:
        {
            "version": "3.0.4",  # seccompute package version
            "syscalls": {
                "bpf": {
                    "tier": 1,
                    "category": "process_inspection",
                    "description": "Load and interact with eBPF programs...",
                    "threats": [
                        {"id": "CVE-2021-3490", "description": "..."},
                        ...
                    ],
                },
                ...
            },
            "combos": [
                {
                    "id": "COMBO-io-uring-network-bypass",
                    "name": "io_uring network bypass",
                    "syscalls": ["io_uring_setup", "io_uring_enter"],
                    "severity": "HIGH",
                    ...
                },
                ...
            ],
            "conditionals": [
                {
                    "syscall": "clone",
                    "condition": "argument_filter",
                    "description": "clone with CLONE_NEWUSER flag...",
                },
                ...
            ],
        }
    """
    import importlib.metadata

    from .rules import load_all_rules

    rules = load_all_rules()

    # Build stable output shape from internal rules.
    # Each syscall entry gets tier, category, description, and threats.
    syscalls: dict = {}
    for name, entry in rules["syscalls"].items():
        syscalls[name] = {
            "tier": entry["tier"],
            "category": entry["category"],
            "description": entry["description"],
            "threats": entry.get("threats", []),
        }

    return {
        "version": importlib.metadata.version("seccompute"),
        "syscalls": syscalls,
        "combos": rules["combos"],
        "conditionals": rules["conditionals"],
    }
