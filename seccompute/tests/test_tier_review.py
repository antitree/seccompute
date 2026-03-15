"""Tier assignment review file for antitree.

This file contains ONLY debatable syscall tier assignments where reasonable
security practitioners could disagree. Obvious assignments are excluded:

EXCLUDED (obviously Tier 1): bpf, ptrace, kexec_load, kexec_file_load,
    init_module, finit_module, delete_module, process_vm_readv, process_vm_writev

EXCLUDED (obviously Tier 2): mount, umount, umount2, setns, pivot_root,
    open_by_handle_at

EXCLUDED (obviously Tier 3): reboot, vhangup, syslog

For each entry below, change suggested_tier to confirmed_tier after review.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.rules import get_tier


@pytest.mark.parametrize("syscall,suggested_tier,reasoning", [
    # -- clone/clone3: Standard process creation but namespace creation flags are dangerous --
    ("clone", 3,
     "Standard for fork/process creation. Dangerous only with CLONE_NEWUSER flag. "
     "All major runtimes arg-filter clone to block namespace flags. "
     "Argument for T2: CLONE_NEWUSER enables user namespace creation which is a "
     "prerequisite for many kernel LPEs. "
     "Argument for T3: Without namespace flags, clone is just fork()."),

    ("clone3", 3,
     "Newer clone API. Docker returns ENOSYS without CAP_SYS_ADMIN. "
     "Argument for T2: Harder to arg-filter than clone (uses struct). "
     "Argument for T3: Same fundamental operation as clone, mostly blocked anyway."),

    # -- io_uring: Massive attack surface but requires setup first --
    ("io_uring_setup", 2,
     "Argument for T1: io_uring bypasses seccomp for registered ops, massive CVE history. "
     "Google blocks it entirely even in production. "
     "Argument for T2: Requires initial setup call, many exploits need chained operations. "
     "Current: T2 because it needs io_uring_enter to be useful."),

    ("io_uring_enter", 2,
     "Argument for T1: This is the syscall that actually submits operations that bypass seccomp. "
     "Argument for T2: Useless without io_uring_setup. Same tier as setup."),

    ("io_uring_register", 2,
     "Argument for T1: Registers resources that bypass seccomp filtering. "
     "Argument for T2: Useless without io_uring_setup. Same tier as setup."),

    # -- unshare: creates namespaces, prerequisite for many exploits --
    ("unshare", 2,
     "Argument for T1: User namespace creation via unshare is THE prerequisite for "
     "nearly every modern kernel LPE from containers. CVE-2022-0185 used it. "
     "Argument for T2: Can also create non-user namespaces which are less dangerous. "
     "The syscall itself doesn't cause the exploit, it's the enabler."),

    # -- keyctl family: recurring UAF vulns --
    ("keyctl", 2,
     "Argument for T1: CVE-2016-0728 was a direct LPE via keyctl. The kernel keyring "
     "has had recurring UAF vulnerabilities. "
     "Argument for T2: Modern kernels have mitigated most known keyring UAFs. "
     "The attack surface exists but is shrinking."),

    ("add_key", 2,
     "Argument for T1: Entry point for keyring exploits (paired with keyctl). "
     "Argument for T2: Requires keyctl to actually exploit. Same tier as keyctl."),

    ("request_key", 2,
     "Argument for T1: Part of keyring exploit chain. "
     "Argument for T2: Least dangerous of the keyring trio. Same tier for consistency."),

    # -- perf_event_open: large attack surface --
    ("perf_event_open", 2,
     "Argument for T1: Multiple CVEs (2022-1729, 2023-2002), large kernel attack surface. "
     "Can be used for side-channel attacks. "
     "Argument for T2: Requires CAP_SYS_ADMIN or CAP_PERFMON in most configurations. "
     "perf_event_paranoid sysctl limits unprivileged use."),

    # -- chroot: limited impact in namespace context --
    ("chroot", 3,
     "Argument for T2: Classic escape technique (chroot breakout). "
     "Combined with mount, can escape filesystem isolation. "
     "Argument for T3: Well-understood, limited impact inside mount namespaces. "
     "Pivot_root is the real threat; chroot escape is mostly a CTF technique."),

    # -- modify_ldt: x86-only, historical exploit surface --
    ("modify_ldt", 3,
     "Argument for T2: CVE-2017-5123 was a real LDT UAF. Modifies segment descriptors "
     "which can affect kernel code execution paths. "
     "Argument for T3: x86-only, modern kernels have significant mitigations. "
     "Exploit complexity is very high on recent kernels."),

    # -- move_mount/open_tree/fsopen/fsmount/fsconfig/fspick: new mount API --
    ("move_mount", 2,
     "Argument for T1: Part of mount escape chain. mount is T2 but this is the new API "
     "that some security tools may not monitor. "
     "Argument for T2: Same fundamental risk as mount(). Consistent tiering."),

    ("fsconfig", 2,
     "Argument for T1: CVE-2022-0185 was a real container escape via fsconfig heap overflow. "
     "This specific syscall has caused production container escapes. "
     "Argument for T2: The CVE was patched. Same tier as mount family for consistency."),

    # -- quotactl: limited risk --
    ("quotactl", 3,
     "Argument for T2: Can manipulate disk quotas which could be used for resource abuse. "
     "Argument for T3: Limited attack surface, mostly DoS potential. "
     "Requires CAP_SYS_ADMIN in practice. No known exploit chains."),

    # -- acct: low risk --
    ("acct", 3,
     "Argument for T2: Process accounting writes to an attacker-specified file, "
     "could be used for controlled writes. "
     "Argument for T3: Very limited information disclosure. Requires CAP_SYS_PACCT."),

    # -- pidfd_getfd: cross-process fd access --
    ("pidfd_getfd", 3,
     "Argument for T2: Steals file descriptors from other processes, crossing process "
     "isolation boundaries. Could steal sockets, opened files. "
     "Argument for T3: Requires CAP_SYS_PTRACE. Similar to /proc/pid/fd but via pidfd."),

    # -- mbind/migrate_pages/move_pages: NUMA operations --
    ("mbind", 3,
     "Argument for T2: Can influence memory layout of other processes on NUMA systems. "
     "Potential for side-channel attacks. "
     "Argument for T3: Requires CAP_SYS_NICE for some policies. Mostly DoS impact."),

    ("migrate_pages", 3,
     "Argument for T2: Can migrate another process's pages between NUMA nodes. "
     "Cross-process memory manipulation. "
     "Argument for T3: Very limited practical exploit potential. DoS only."),

    ("move_pages", 3,
     "Argument for T2: Fine-grained page placement for side-channel potential. "
     "Argument for T3: Research-grade attack only. No known practical exploits."),

    # -- iopl/ioperm: hardware access --
    ("iopl", 3,
     "Argument for T2: Grants ring-0-like I/O access on x86. Could read/write "
     "hardware ports directly. "
     "Argument for T3: x86-only. Mitigated by virtualization in cloud environments. "
     "Requires CAP_SYS_RAWIO which is almost never granted."),

    ("ioperm", 3,
     "Argument for T2: Per-port I/O access, same hardware risk as iopl. "
     "Argument for T3: Same mitigations as iopl. More granular but same risk class."),

    # -- time manipulation --
    ("settimeofday", 3,
     "Argument for T2: Affects ALL containers and host. Can break TLS cert validation, "
     "TOTP, time-based security mechanisms. Not namespaced. "
     "Argument for T3: No code execution. Requires CAP_SYS_TIME. DoS/confusion only."),

    ("clock_settime", 3,
     "Argument for T2: Same host-wide time manipulation as settimeofday. "
     "Argument for T3: Same reasoning as settimeofday."),

    # -- hostname: UTS namespace contained --
    ("sethostname", 3,
     "Argument for T2: Could confuse service discovery or monitoring. "
     "Argument for T3: Contained in UTS namespace. Requires CAP_SYS_ADMIN. Minimal impact."),

    ("setdomainname", 3,
     "Same reasoning as sethostname. NIS domain name is even less impactful."),
])
def test_tier_assignment_review(syscall, suggested_tier, reasoning):
    """TODO: antitree to validate. Change suggested_tier to confirmed value when reviewed."""
    assert get_tier(syscall) == suggested_tier
