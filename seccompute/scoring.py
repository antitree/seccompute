"""Core scoring engine for seccompute.

Orchestrates the scoring pipeline: load rules, resolve states, compute score,
detect combos, apply grading and forced-failure logic.
"""
from __future__ import annotations

import re
from typing import Any

from .combos import evaluate_combos
from .conditionals import analyze_conditionals, resolve_effective_states
from .grader import check_forced_failure, compute_grade
from .model import (
    ENGINE_VERSION,
    SCHEMA_VERSION,
    ComboFinding,
    ConditionalFinding,
    ScoringResult,
    TierFinding,
)
from .rules import load_all_rules
from .tiers import TIER_BUDGETS, build_tiers, build_weights, get_all_dangerous

# Arch-specific prefixes that some profile generators emit.
# Strip these before any lookup so "I386.read" → "read", "x32.mmap" → "mmap".
_ARCH_PREFIXES = ("I386.x32.", "I386.", "x32.")


def _strip_arch_prefix(name: str) -> str:
    """Strip architecture namespace prefixes from a syscall name."""
    for prefix in _ARCH_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


# Known safe syscalls that should not generate unknown warnings.
# Includes 64-bit canonical names plus common 32-bit aliases and arch-specific
# variants that appear in real-world profiles from the Docker/Moby dataset.
_KNOWN_SAFE: frozenset[str] = frozenset([
    # --- Standard 64-bit syscalls ---
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
    "lseek", "mmap", "mprotect", "munmap", "brk", "ioctl", "access",
    "pipe", "select", "sched_yield", "mremap", "msync", "mincore",
    "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "dup3",
    "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid",
    "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
    "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname",
    "getpeername", "socketpair", "setsockopt", "getsockopt", "fork",
    "vfork", "execve", "exit", "wait4", "kill", "uname", "semget",
    "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl",
    "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate",
    "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir",
    "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod",
    "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
    "getrusage", "sysinfo", "times", "getuid", "getgid", "setuid",
    "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
    "setsid", "setreuid", "setregid", "getgroups", "setgroups",
    "setresuid", "getresuid", "setresgid", "getresgid", "getpgid",
    "setfsuid", "setfsgid", "getsid", "capget", "capset",
    "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend",
    "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat",
    "statfs", "fstatfs", "sysfs", "getpriority", "setpriority",
    "sched_setparam", "sched_getparam", "sched_setscheduler",
    "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
    "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall",
    "prctl", "arch_prctl", "adjtimex", "setrlimit", "sync",
    "mount_setattr", "gettid", "readahead", "setxattr", "lsetxattr",
    "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
    "llistxattr", "flistxattr", "removexattr", "lremovexattr",
    "fremovexattr", "tkill", "time", "futex", "sched_setaffinity",
    "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy",
    "io_getevents", "io_submit", "io_cancel", "get_thread_area",
    "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old",
    "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall",
    "semtimedop", "fadvise64", "timer_create", "timer_settime",
    "timer_gettime", "timer_getoverrun", "timer_delete", "clock_gettime",
    "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait",
    "epoll_ctl", "epoll_pwait", "epoll_pwait2", "tgkill", "utimes",
    "waitid", "set_robust_list", "get_robust_list", "splice", "tee",
    "sync_file_range", "vmsplice", "fallocate", "timerfd_settime",
    "timerfd_gettime", "accept4", "signalfd4", "eventfd2",
    "epoll_create1", "pipe2", "inotify_init1", "preadv", "pwritev",
    "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init",
    "fanotify_mark", "prlimit64", "name_to_handle_at", "clock_adjtime",
    "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
    "process_vm_writev", "kcmp", "finit_module", "sched_setattr",
    "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create",
    "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range",
    "preadv2", "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free",
    "statx", "io_pgetevents", "rseq", "pidfd_send_signal", "io_uring_setup",
    "io_uring_enter", "io_uring_register", "open_tree", "move_mount",
    "fsopen", "fsconfig", "fsmount", "fspick", "pidfd_open",
    "openat", "openat2", "close_range", "faccessat2", "process_madvise",
    "epoll_pwait2", "mount_setattr", "quotactl_fd", "landlock_create_ruleset",
    "landlock_add_rule", "landlock_restrict_self", "memfd_secret",
    "process_mrelease", "futex_waitv", "set_mempolicy_home_node",
    "cachestat", "fchmodat2", "map_shadow_stack", "futex_wake",
    "futex_wait", "futex_requeue", "readlinkat", "newfstatat",
    "fchownat", "unlinkat", "mkdirat", "mknodat", "fchmodat",
    "faccessat", "utimensat", "linkat", "symlinkat", "rt_sigaction",
    "rt_sigprocmask", "rt_sigreturn", "pread64", "pwrite64",
    "readv", "writev", "ppoll", "pselect6", "signalfd",
    "timerfd_create", "eventfd", "inotify_init", "inotify_add_watch",
    "inotify_rm_watch", "pidfd_getfd",
    # --- 32-bit compat aliases (i386 / arm32 / mips-o32) ---
    # These are equivalent to their 64-bit counterparts and carry no extra risk.
    "mmap2", "fcntl64", "stat64", "fstat64", "lstat64", "fstatat64",
    "statfs64", "fstatfs64", "ftruncate64", "lstat64", "truncate64",
    "fadvise64_64", "sendfile64", "ugetrlimit",
    "getuid32", "getgid32", "geteuid32", "getegid32",
    "getresuid32", "getresgid32", "getgroups32", "setgroups32",
    "setuid32", "setgid32", "setreuid32", "setregid32",
    "setresuid32", "setresgid32", "setfsuid32", "setfsgid32",
    "chown32", "lchown32", "fchown32",
    # --- POSIX / compat syscalls present in older kernels ---
    "renameat",       # older rename-at (before renameat2)
    "futimesat",      # older utimes variant
    "pread", "pwrite",  # older pread64/pwrite64 aliases
    "send", "recv",   # older sendto/recvfrom aliases
    "sigreturn", "_newselect", "_llseek",
    "waitpid",        # older wait4 alias
    "ipc",            # multiplexed SysV IPC (older kernels)
    "socketcall",     # multiplexed socket calls (older kernels / i386)
    "sigprocmask", "sigpending", "sigsuspend", "sigaction", "signal",
    "readdir",        # old getdents variant
    "newuname", "newstat", "newfstat", "newlstat",
    "fstatat",        # older newfstatat alias
    "_sysctl",        # removed in 5.5 but still in profiles
    "get_kernel_syms", "create_module", "query_module",  # legacy module syscalls
    "nfsservctl",     # removed in 3.1
    "timerfd",        # old timerfd (before timerfd_create)
    # --- Arch-specific (ARM, s390, RISC-V) ---
    "set_tls", "cacheflush", "breakpoint",  # ARM
    "arm_fadvise64_64", "arm_sync_file_range", "sync_file_range2",  # ARM
    "swapcontext",    # PowerPC
    "s390_pci_mmio_read", "s390_pci_mmio_write", "s390_runtime_instr",  # s390
    "riscv_flush_icache", "riscv_hwprobe",  # RISC-V
    # --- time64 variants (32-bit kernels / compat) ---
    "clock_gettime64", "clock_settime64", "clock_adjtime64",
    "clock_getres_time64", "clock_nanosleep_time64",
    "timer_gettime64", "timer_settime64",
    "timerfd_gettime64", "timerfd_settime64",
    "utimensat_time64", "pselect6_time64", "ppoll_time64",
    "recvmmsg_time64", "semtimedop_time64", "rt_sigtimedwait_time64",
    "futex_time64", "sched_rr_get_interval_time64",
    "mq_timedreceive_time64", "mq_timedsend_time64",
    "io_pgetevents_time64",
    # --- POSIX message queues ---
    "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
    "mq_notify", "mq_getsetattr",
    # --- I/O priority ---
    "ioprio_set", "ioprio_get",
    # --- NUMA memory policy (non-dangerous variant) ---
    "get_mempolicy", "set_mempolicy",
    # --- Misc legacy / obscure but benign ---
    "stime",          # set time (very old)
    "uselib",         # load shared library (ancient)
    "readdirent",     # old readdir alias
    "vserver",        # never implemented
    "afs_syscall", "tuxcall", "security",  # reserved/unimplemented stubs
    "getpmsg", "putpmsg",  # STREAMS (never implemented on Linux)
    "vm86", "vm86old",  # VM86 mode (x86 only, benign)
    "seteuid", "setegid",  # POSIX wrappers (glibc uses setreuid internally)
    "setpgrp",        # alias for setpgid(0,0)
    "wait", "wait3",  # old wait variants
    "lockf",          # POSIX file locking (uses fcntl internally)
    "mkfifo",         # named pipe creation
    "raise",          # signal to self
    "unknown_syscall",  # placeholder in some generated profiles
    # --- Linux 6.x new syscalls ---
    "mseal",          # memory sealing (6.10)
    "listmount",      # list mounts (6.8)
    "statmount",      # stat mount (6.8)
    "uretprobe",      # uprobe return (6.8)
    # xattr-at variants (6.13+)
    "getxattrat", "setxattrat", "listxattrat", "removexattrat",
    # LSM attribute syscalls (6.8)
    "lsm_get_self_attr", "lsm_set_self_attr", "lsm_list_modules",
])

# State multipliers
_STATE_MULT: dict[str, float] = {
    "blocked": 0.0,
    "conditional": 0.5,
    "allowed": 1.0,
}

# T1 conditional is more dangerous in standard mode
_T1_CONDITIONAL_MULT = 0.75


def _extract_annotations(profile: dict) -> tuple[set[str], dict[str, str]]:
    """Extract x-seccompute annotation overrides.

    Returns (overridden_syscalls, justifications_map).
    """
    x_sec = profile.get("x-seccompute", {})
    if not isinstance(x_sec, dict):
        return set(), {}

    overrides: set[str] = set()
    justifications: dict[str, str] = {}

    # New format: intent.syscalls.<name>.justification
    intent = x_sec.get("intent", {})
    if isinstance(intent, dict):
        syscalls = intent.get("syscalls", {})
        if isinstance(syscalls, dict):
            for name, data in syscalls.items():
                if isinstance(data, dict):
                    j = data.get("justification", "")
                    if j:
                        overrides.add(name)
                        justifications[name] = j

    # Legacy format: allow list
    allow = x_sec.get("allow", [])
    if isinstance(allow, list):
        for name in allow:
            if isinstance(name, str):
                overrides.add(name)

    return overrides, justifications


def score_profile(
    profile: dict,
    *,
    arch: str = "SCMP_ARCH_X86_64",
    rules_dir: str | None = None,
    granted_caps: frozenset[str] | None = None,
) -> ScoringResult:
    """Score a seccomp profile on a 0-100 hardening scale.

    Args:
        profile: OCI seccomp profile dict (already normalized).
        arch: Target architecture (stored in metadata).
        rules_dir: Override rules directory. Also settable via SECCOMPUTE_RULES_DIR env.

    Returns:
        ScoringResult with score, grade, findings, and metadata.
    """
    all_rules = load_all_rules(rules_dir)
    syscall_rules = all_rules["syscalls"]
    combo_rules_data = all_rules["combos"]

    # Build tier structures
    tiers = build_tiers(syscall_rules)
    weights = build_weights(tiers)
    all_dangerous = get_all_dangerous(tiers)
    tier1_members = tiers.get(1, [])

    # Collect all syscalls mentioned in the profile, stripping arch prefixes.
    # Some profile generators emit names like "I386.read" or "x32.mmap".
    profile_syscalls: set[str] = set()
    for rule in profile.get("syscalls", []):
        for name in rule.get("names", []):
            if isinstance(name, str):
                profile_syscalls.add(_strip_arch_prefix(name))

    # Detect unknown syscalls
    warnings: list[str] = []
    unknown_active: set[str] = set()
    default_action = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    permissive_default = default_action in {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}

    for sc in profile_syscalls:
        if sc in all_dangerous or sc in syscall_rules or sc in _KNOWN_SAFE:
            continue
        # Skip numeric stubs (hex literals, "syscall452", "syscall_1f4", etc.)
        # that are artifacts of profile generators and have no known semantics.
        if re.match(r'^(0x[0-9a-fA-F]+|syscall[_]?[0-9a-fA-F]+)$', sc):
            continue
        # Unknown syscall - check if effectively allowed
        explicitly_allowed = False
        explicitly_blocked = False
        for rule in profile.get("syscalls", []):
            if sc in rule.get("names", []):
                action = rule.get("action", "")
                if action in {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}:
                    explicitly_allowed = True
                elif action in {"SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS",
                                "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP"}:
                    explicitly_blocked = True

        if explicitly_allowed or (permissive_default and not explicitly_blocked):
            unknown_active.add(sc)
            t2_budget = TIER_BUDGETS.get(2, 10.0)
            t2_count = len(tiers.get(2, []))
            unknown_weight = t2_budget / t2_count if t2_count else 0.0
            warnings.append(
                f"Unknown syscall '{sc}' not in rules. "
                f"Scored conservatively as T2 (weight={unknown_weight:.2f})."
            )

    # Collect all bypass syscalls from combo rules so their states are resolved
    combo_bypass_syscalls: set[str] = set()
    for cr in combo_rules_data:
        combo_bypass_syscalls.update(cr.get("bypasses", []))
        combo_bypass_syscalls.update(cr.get("syscalls", []))

    # Resolve effective states for all scored syscalls + combo-relevant syscalls
    score_set = all_dangerous | unknown_active
    resolve_set = score_set | profile_syscalls | combo_bypass_syscalls
    states = resolve_effective_states(profile, frozenset(resolve_set), granted_caps=granted_caps)

    # Analyze conditionals
    conditional_findings = analyze_conditionals(profile, granted_caps=granted_caps)

    # Evaluate combo rules
    combo_findings = evaluate_combos(profile, states, combo_rules_data)

    # Extract annotations
    annotation_overrides, justifications = _extract_annotations(profile)

    # Compute score
    total_deduction = 0.0
    tier_findings: list[TierFinding] = []
    tier_exposed: dict[int, int] = {1: 0, 2: 0, 3: 0}

    for sc in sorted(all_dangerous):
        state = states.get(sc, "blocked")
        rule_data = syscall_rules.get(sc, {})
        tier_num = rule_data.get("tier", 0)
        weight = weights.get(sc, 0.0)

        # T1 conditional is 0.75 in standard mode
        if tier_num == 1 and state == "conditional":
            mult = _T1_CONDITIONAL_MULT
        else:
            mult = _STATE_MULT.get(state, 0.0)

        deduction = weight * mult
        total_deduction += deduction

        if tier_num in tier_exposed and state != "blocked":
            tier_exposed[tier_num] += 1

        # Build finding for exposed syscalls
        if state != "blocked":
            threats = rule_data.get("threats", [])
            exploit_paths = [t.get("id", "") for t in threats if isinstance(t, dict)]
            tier_findings.append(TierFinding(
                syscall=sc,
                tier=tier_num,
                state=state,
                weight=weight,
                deduction=deduction,
                description=rule_data.get("description", ""),
                exploit_paths=exploit_paths,
                justification=justifications.get(sc),
            ))

    # Score unknown active syscalls
    for sc in sorted(unknown_active):
        state = states.get(sc, "blocked")
        t2_budget = TIER_BUDGETS.get(2, 10.0)
        t2_count = len(tiers.get(2, []))
        unknown_weight = t2_budget / t2_count if t2_count else 0.0
        mult = _STATE_MULT.get(state, 0.0)
        deduction = unknown_weight * mult
        total_deduction += deduction

        if state != "blocked":
            tier_findings.append(TierFinding(
                syscall=sc,
                tier=0,
                state=state,
                weight=unknown_weight,
                deduction=deduction,
                description=f"Unknown syscall scored as T2 equivalent",
                exploit_paths=[],
            ))

    raw_score = 100.0 - total_deduction
    score = max(0, min(100, round(raw_score)))

    # Grade and forced failure
    forced_failure, ff_reasons = check_forced_failure(
        tier1_members, states, annotation_overrides
    )
    grade = "F" if forced_failure else compute_grade(score)

    tier_summary = {
        "t1_exposed": tier_exposed.get(1, 0),
        "t2_exposed": tier_exposed.get(2, 0),
        "t3_exposed": tier_exposed.get(3, 0),
    }

    metadata: dict[str, Any] = {
        "engine_version": ENGINE_VERSION,
        "arch": arch,
        "schema_version": SCHEMA_VERSION,
        "rules_dir": rules_dir,
        "granted_caps": sorted(granted_caps) if granted_caps is not None else None,
    }

    return ScoringResult(
        score=score,
        grade=grade,
        forced_failure=forced_failure,
        forced_failure_reasons=ff_reasons,
        annotation_overrides=sorted(annotation_overrides & set(tier1_members)),
        scoring_mode="standard",
        tier_summary=tier_summary,
        tier_findings=tier_findings,
        combo_findings=combo_findings,
        conditional_findings=conditional_findings,
        warnings=warnings,
        metadata=metadata,
    )
