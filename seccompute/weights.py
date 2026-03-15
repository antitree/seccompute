"""Shipped dangerous syscall set and weight pack (default_v1).

Verbatim from analyze_profiles.py — do not customize for v2.
"""

WEIGHTS_PACK = "default_v1"

# Dangerous syscalls for container breakout / host compromise
DANGEROUS_SYSCALLS = {
    "bpf", "mount", "umount", "umount2", "chroot", "ptrace", "unshare",
    "setns", "pivot_root", "reboot", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module", "acct",
    "open_by_handle_at", "clone", "clone3", "perf_event_open",
    "process_vm_readv", "process_vm_writev", "modify_ldt",
    "iopl", "ioperm", "swapon", "swapoff", "sethostname", "setdomainname",
    "settimeofday", "clock_settime", "vhangup", "syslog",
    "move_mount", "open_tree", "fsopen", "fsmount", "fsconfig", "fspick",
    "pidfd_getfd", "io_uring_setup", "io_uring_enter", "io_uring_register",
    "mbind", "migrate_pages", "move_pages", "quotactl",
    "add_key", "keyctl", "request_key",
}

# Weights for high-risk syscalls emphasizing direct exploit surface
HIGH_RISK_WEIGHTS = {
    # Critical exploitation surfaces
    "bpf": 3.0,
    "ptrace": 3.0,
    "perf_event_open": 3.0,
    "process_vm_readv": 3.0,
    "process_vm_writev": 3.0,
    "io_uring_setup": 3.0,
    "io_uring_enter": 3.0,
    "io_uring_register": 3.0,
    "open_by_handle_at": 3.0,
    "init_module": 3.0,
    "finit_module": 3.0,
    "delete_module": 3.0,
    "kexec_load": 3.0,
    "kexec_file_load": 3.0,
    # Filesystem / namespace breakout vectors
    "mount": 3.0,
    "umount": 3.0,
    "umount2": 3.0,
    "move_mount": 3.0,
    "open_tree": 3.0,
    "fsopen": 3.0,
    "fsmount": 3.0,
    "fsconfig": 3.0,
    "fspick": 3.0,
    "setns": 3.0,
    "unshare": 3.0,
    "pivot_root": 3.0,
    # Kernel keyring abuse
    "add_key": 3.0,
    "keyctl": 3.0,
    "request_key": 3.0,
    # Elevated but slightly less direct (still dangerous)
    "chroot": 2.0,
    "clone": 2.0,
    "clone3": 2.0,
    "iopl": 2.0,
    "ioperm": 2.0,
    "swapon": 2.0,
    "swapoff": 2.0,
    "sethostname": 2.0,
    "setdomainname": 2.0,
    "settimeofday": 2.0,
    "clock_settime": 2.0,
    "vhangup": 2.0,
    "syslog": 2.0,
    "pidfd_getfd": 2.0,
    "mbind": 2.0,
    "migrate_pages": 2.0,
    "move_pages": 2.0,
    "quotactl": 2.0,
    "acct": 2.0,
    "reboot": 2.0,
}

for _sc, _w in HIGH_RISK_WEIGHTS.items():
    if _w < 0:
        raise ValueError(f"HIGH_RISK_WEIGHTS['{_sc}'] must be non-negative, got {_w}")
