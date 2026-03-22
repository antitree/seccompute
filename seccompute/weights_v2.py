"""Tiered dangerous syscall weights for threat_v2 scoring model.

Three tiers with fixed budget allocations summing to 100:
  - Tier 1 (60): catastrophic — container escape / kernel code exec
  - Tier 2 (30): serious — namespace/filesystem escape vectors
  - Tier 3 (10): elevated — contextual risk

Per-syscall weight = tier_budget / len(tier_syscalls), computed dynamically
so syscalls can be moved between tiers without changing budget constants.
"""

from __future__ import annotations

WEIGHTS_PACK_V2 = "threat_v2"

TOTAL_KNOWN_SYSCALLS = 462

TIER1_BUDGET = 85
TIER2_BUDGET = 10
TIER3_BUDGET = 5

TIER1: list[str] = [
    "bpf", "ptrace", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module",
    "process_vm_readv", "process_vm_writev",
]  # 9 syscalls

TIER2: list[str] = [
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "mount", "umount", "umount2", "move_mount", "open_tree",
    "fsopen", "fsmount", "fsconfig", "fspick",
    "setns", "unshare", "pivot_root", "open_by_handle_at",
    "keyctl", "add_key", "request_key", "perf_event_open",
]  # 20 syscalls

TIER3: list[str] = [
    "clone", "clone3", "chroot",
    "iopl", "ioperm", "reboot",
    "swapon", "swapoff", "sethostname", "setdomainname",
    "settimeofday", "clock_settime", "vhangup",
    "syslog", "pidfd_getfd", "mbind", "migrate_pages",
    "move_pages", "quotactl", "acct", "modify_ldt",
]  # 21 syscalls

ALL_DANGEROUS_V2: frozenset[str] = frozenset(TIER1 + TIER2 + TIER3)

for _name, _val in [("TIER1_BUDGET", TIER1_BUDGET), ("TIER2_BUDGET", TIER2_BUDGET), ("TIER3_BUDGET", TIER3_BUDGET)]:
    if _val < 0:
        raise ValueError(f"{_name} must be non-negative, got {_val}")

# Pre-compute per-syscall weights
_TIER_WEIGHTS: dict[str, float] = {}
for _tier, _budget in [(TIER1, TIER1_BUDGET), (TIER2, TIER2_BUDGET), (TIER3, TIER3_BUDGET)]:
    if not _tier:
        raise ValueError(f"Tier with budget {_budget} has no syscalls; cannot compute weights")
    for _sc in _tier:
        _TIER_WEIGHTS[_sc] = _budget / len(_tier)


def tier_weight(syscall: str) -> float:
    """Return the per-syscall penalty weight, or 0.0 if not in any tier."""
    return _TIER_WEIGHTS.get(syscall, 0.0)
