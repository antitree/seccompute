"""CLI entry point for seccompute scoring engine.

Usage:
    python -m seccompute profile.json [--arch ARCH] [--format json|text]
                                       [--min-score N] [--grade] [--verbose]

Exit codes:
    0 - Success
    1 - Error (file not found, invalid input, runtime error)
    2 - Score below --min-score threshold
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .normalizer import normalize, validate
from .scoring import score_profile

# Docker/Moby default seccomp profile — syscalls allowed by default.
# Source: https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
# Last updated: Docker 27.x / Moby main (2025-01)
# This is the union of all allowed syscall names in the default profile.
_DOCKER_DEFAULT_ALLOWED: frozenset[str] = frozenset([
    "accept", "accept4", "access", "adjtimex", "alarm", "bind", "brk",
    "capget", "capset", "chdir", "chmod", "chown", "chown32", "clock_adjtime",
    "clock_adjtime64", "clock_getres", "clock_getres_time64", "clock_gettime",
    "clock_gettime64", "clock_nanosleep", "clock_nanosleep_time64", "close",
    "close_range", "connect", "copy_file_range", "creat", "dup", "dup2", "dup3",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old", "epoll_pwait",
    "epoll_pwait2", "epoll_wait", "epoll_wait_old", "eventfd", "eventfd2",
    "execve", "execveat", "exit", "exit_group", "faccessat", "faccessat2",
    "fadvise64", "fadvise64_64", "fallocate", "fanotify_mark", "fchdir",
    "fchmod", "fchmodat", "fchmodat2", "fchown", "fchown32", "fchownat",
    "fcntl", "fcntl64", "fdatasync", "fgetxattr", "flistxattr", "flock",
    "fork", "fremovexattr", "fsetxattr", "fstat", "fstat64", "fstatat64",
    "fstatfs", "fstatfs64", "fsync", "ftruncate", "ftruncate64", "futex",
    "futex_time64", "futex_waitv", "futimesat", "getcpu", "getcwd",
    "getdents", "getdents64", "getegid", "getegid32", "geteuid", "geteuid32",
    "getgid", "getgid32", "getgroups", "getgroups32", "getitimer",
    "getpeername", "getpgid", "getpgrp", "getpid", "getppid", "getpriority",
    "getrandom", "getresgid", "getresgid32", "getresuid", "getresuid32",
    "getrlimit", "getrusage", "getsid", "getsockname", "getsockopt",
    "gettid", "gettimeofday", "getuid", "getuid32", "getxattr", "inotify_add_watch",
    "inotify_init", "inotify_init1", "inotify_rm_watch", "io_cancel",
    "io_destroy", "io_getevents", "io_pgetevents", "io_pgetevents_time64",
    "io_setup", "io_submit", "io_uring_enter", "io_uring_register",
    "io_uring_setup", "ioctl", "ioprio_get", "ioprio_set", "ipc",
    "kill", "landlock_add_rule", "landlock_create_ruleset",
    "landlock_restrict_self", "lchown", "lchown32", "lgetxattr", "link",
    "linkat", "listen", "listxattr", "llistxattr", "lremovexattr", "lseek",
    "lsetxattr", "lstat", "lstat64", "madvise", "membarrier", "memfd_create",
    "memfd_secret", "mincore", "mkdir", "mkdirat", "mknod", "mknodat",
    "mlock", "mlock2", "mlockall", "mmap", "mmap2", "mprotect", "mq_getsetattr",
    "mq_notify", "mq_open", "mq_timedreceive", "mq_timedreceive_time64",
    "mq_timedsend", "mq_timedsend_time64", "mq_unlink", "mremap", "msgctl",
    "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap",
    "nanosleep", "newfstatat", "open", "openat", "openat2", "pause",
    "pidfd_getfd", "pidfd_open", "pidfd_send_signal", "pipe", "pipe2",
    "poll", "ppoll", "ppoll_time64", "prctl", "pread64", "preadv",
    "preadv2", "prlimit64", "process_mrelease", "pselect6", "pselect6_time64",
    "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink",
    "readlinkat", "readv", "recv", "recvfrom", "recvmmsg",
    "recvmmsg_time64", "recvmsg", "remap_file_pages", "removexattr",
    "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rseq",
    "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo",
    "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait",
    "rt_sigtimedwait_time64", "rt_tgsigqueueinfo", "sched_getaffinity",
    "sched_getattr", "sched_getparam", "sched_get_priority_max",
    "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval",
    "sched_rr_get_interval_time64", "sched_setaffinity", "sched_setattr",
    "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp",
    "select", "semctl", "semget", "semop", "semtimedop", "semtimedop_time64",
    "send", "sendfile", "sendfile64", "sendmmsg", "sendmsg", "sendto",
    "set_mempolicy", "set_mempolicy_home_node", "set_robust_list",
    "set_thread_area", "set_tid_address", "setfsgid", "setfsgid32",
    "setfsuid", "setfsuid32", "setgid", "setgid32", "setgroups",
    "setgroups32", "setitimer", "setpgid", "setpriority", "setregid",
    "setregid32", "setresgid", "setresgid32", "setresuid", "setresuid32",
    "setreuid", "setreuid32", "setrlimit", "setsid", "setsockopt",
    "setuid", "setuid32", "setxattr", "shmat", "shmctl", "shmdt", "shmget",
    "sigaltstack", "signalfd", "signalfd4", "sigprocmask", "sigreturn",
    "socket", "socketcall", "socketpair", "splice", "stat", "stat64",
    "statfs", "statfs64", "statx", "symlink", "symlinkat", "sync",
    "sync_file_range", "syncfs", "tee", "tgkill", "time", "timer_create",
    "timer_delete", "timer_getoverrun", "timer_gettime", "timer_gettime64",
    "timer_settime", "timer_settime64", "timerfd_create", "timerfd_gettime",
    "timerfd_gettime64", "timerfd_settime", "timerfd_settime64", "times",
    "tkill", "truncate", "truncate64", "ugetrlimit", "umask", "uname",
    "unlink", "unlinkat", "utime", "utimensat", "utimensat_time64", "utimes",
    "vfork", "vmsplice", "wait4", "waitid", "waitpid", "write", "writev",
])


def _parse_caps(raw: str | None) -> "frozenset[str] | None":
    """Parse --caps argument into a frozenset of normalized cap names.

    Returns None if raw is None (flag not provided — no caps context).
    Returns frozenset() if raw is empty string (explicit zero caps granted).
    Returns frozenset of uppercased cap names otherwise.
    """
    if raw is None:
        return None
    if not raw.strip():
        return frozenset()
    return frozenset(c.strip().upper() for c in raw.split(",") if c.strip())


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="seccompute",
        description="Score a seccomp profile on a 0-100 hardening scale.",
    )

    parser.add_argument("profile", nargs="?", default="-", help="Path to seccomp profile (JSON or YAML), or - for stdin")
    parser.add_argument("--arch", default="SCMP_ARCH_X86_64", help="Target architecture (default: SCMP_ARCH_X86_64)")
    parser.add_argument("--min-score", type=int, default=None, metavar="N", help="Exit 2 if score is below N (for CI gates)")
    parser.add_argument("--compare-docker", action="store_true", help="Compare profile against Docker/Moby default seccomp allowlist and show delta")
    parser.add_argument("--rules", default=None, metavar="DIR", help="Directory containing custom rule files (syscall_rules.yaml, combo_rules.yaml, conditional_rules.yaml); falls back to built-ins for any file not present")
    parser.add_argument(
        "--caps",
        default=None,
        metavar="CAPS",
        help=(
            "Comma-separated capabilities granted to the container "
            "(e.g. CAP_BPF,CAP_SYS_ADMIN). When provided, capability-conditional "
            "rules are resolved against this set. Use empty string to specify "
            "no capabilities. When omitted, cap conditionals are ignored entirely "
            "so Docker and containerd profiles score equivalently."
        ),
    )

    output = parser.add_argument_group("output")
    output.add_argument("--grade", action="store_true", help="Show letter-grade visualization (ANSI color)")
    output.add_argument("--format", choices=["json", "text"], default="json", help="Output format (default: json)")
    output.add_argument("--json", action="store_true", dest="json_shorthand", help="Shorthand for --format json")
    output.add_argument("--verbose", action="store_true", help="Per-syscall details to stderr")

    ns = parser.parse_args(argv)
    if ns.json_shorthand:
        ns.format = "json"
    return ns


def _load_profile(path: Path) -> dict:
    """Load and auto-detect profile format (JSON or YAML)."""
    raw = path.read_text(encoding="utf-8")

    # Try JSON first
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Try YAML
    try:
        data = yaml.safe_load(raw)
        if isinstance(data, dict):
            return data
    except yaml.YAMLError:
        pass

    raise ValueError("Could not parse profile as JSON or YAML")


def _format_text(result) -> str:
    lines = []
    lines.append(f"Score: {result.score}/100")
    lines.append(f"Grade: {result.grade}")
    if result.forced_failure:
        lines.append(f"FORCED FAILURE: {'; '.join(result.forced_failure_reasons)}")
    ts = result.tier_summary
    lines.append(f"Exposed: T1={ts['t1_exposed']} T2={ts['t2_exposed']} T3={ts['t3_exposed']}")
    if result.combo_findings:
        lines.append(f"Combo findings: {len(result.combo_findings)}")
    if result.warnings:
        lines.append("Warnings:")
        for w in result.warnings:
            lines.append(f"  - {w}")
    lines.append(f"Arch: {result.metadata.get('arch', '?')}  Engine: v{result.metadata.get('engine_version', '?')}")
    return "\n".join(lines)


def _collect_allowed(profile: dict) -> set[str]:
    """Collect syscalls that are explicitly allowed in the profile."""
    from .scoring import _strip_arch_prefix
    allowed: set[str] = set()
    for rule in profile.get("syscalls", []):
        action = rule.get("action", "")
        if action in {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}:
            for name in rule.get("names", []):
                if isinstance(name, str):
                    allowed.add(_strip_arch_prefix(name))
    # If default action is permissive, everything not explicitly blocked is allowed
    default = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    if default in {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_TRACE"}:
        blocked: set[str] = set()
        for rule in profile.get("syscalls", []):
            action = rule.get("action", "")
            if action in {"SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS",
                          "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP"}:
                for name in rule.get("names", []):
                    if isinstance(name, str):
                        blocked.add(_strip_arch_prefix(name))
        allowed = _DOCKER_DEFAULT_ALLOWED - blocked
    return allowed


def _print_docker_comparison(profile: dict, result) -> None:
    """Print a comparison of the profile against the Docker default allowlist."""
    profile_allowed = _collect_allowed(profile)
    docker_allowed = _DOCKER_DEFAULT_ALLOWED

    # What the profile allows that Docker blocks by default (more permissive)
    extra = sorted(profile_allowed - docker_allowed)
    # What Docker allows that this profile blocks (more restrictive)
    removed = sorted(docker_allowed - profile_allowed)

    print(f"Score: {result.score}/100  Grade: {result.grade}")
    if result.forced_failure:
        print(f"FORCED FAILURE: {'; '.join(result.forced_failure_reasons)}")
    print()
    print(f"Docker default allows {len(docker_allowed)} syscalls.")
    print(f"This profile allows  {len(profile_allowed)} syscalls.")
    print()

    if removed:
        print(f"[+] More restrictive than Docker default — {len(removed)} syscalls blocked that Docker allows:")
        for sc in removed:
            print(f"    - {sc}")
        print()
    else:
        print("[=] Profile allows at least all syscalls Docker allows (not more restrictive).")
        print()

    if extra:
        print(f"[-] Less restrictive than Docker default — {len(extra)} extra syscalls allowed:")
        for sc in extra:
            finding_tier = next(
                (f.tier for f in result.tier_findings if f.syscall == sc),
                None,
            )
            tier_label = f"  [T{finding_tier}]" if finding_tier else ""
            print(f"    + {sc}{tier_label}")
        print()

    if not extra and not removed:
        print("[=] Profile is identical to Docker default allowlist.")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.profile == "-":
        # Read from stdin
        raw = sys.stdin.read()
        if not raw.strip():
            print("Error: empty input on stdin", file=sys.stderr)
            return 1
        try:
            raw_data = json.loads(raw)
            if not isinstance(raw_data, dict):
                raise ValueError("Profile must be a JSON or YAML object")
        except json.JSONDecodeError:
            try:
                raw_data = yaml.safe_load(raw)
                if not isinstance(raw_data, dict):
                    raise ValueError("Profile must be a JSON or YAML object")
            except yaml.YAMLError as e:
                print(f"Error: could not parse stdin as JSON or YAML: {e}", file=sys.stderr)
                return 1
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    else:
        profile_path = Path(args.profile)
        if ".." in profile_path.parts:
            print("Error: path traversal not allowed", file=sys.stderr)
            return 1

        if not profile_path.exists():
            print(f"Error: file not found: {profile_path}", file=sys.stderr)
            return 1

        try:
            raw_data = _load_profile(profile_path)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error reading profile: {e}", file=sys.stderr)
            return 1

    try:
        profile = normalize(raw_data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Validate structure — fatal errors (bad defaultAction) raise ValueError,
    # non-fatal issues (bad syscall names, bad rule actions) return warnings.
    try:
        validation_warnings = validate(profile)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    rules_dir = None
    if args.rules is not None:
        rules_path = Path(args.rules)
        if not rules_path.is_dir():
            print(f"Error: --rules must be a directory, got: {args.rules}", file=sys.stderr)
            return 1
        rules_dir = str(rules_path)

    granted_caps = _parse_caps(args.caps)
    result = score_profile(profile, arch=args.arch, rules_dir=rules_dir, granted_caps=granted_caps)

    # Merge validation warnings into the result's warning list so they
    # appear in both JSON and text output without requiring a separate channel.
    if validation_warnings:
        from dataclasses import replace as _dc_replace
        result = _dc_replace(result, warnings=list(result.warnings) + validation_warnings)

    if args.compare_docker:
        _print_docker_comparison(profile, result)
        if args.min_score is not None and result.score < args.min_score:
            return 2
        return 0

    if args.grade:
        from .viz import render_grade
        print(render_grade(result))
        if args.min_score is not None and result.score < args.min_score:
            return 2
        return 0

    if args.verbose:
        for f in result.tier_findings:
            print(json.dumps({
                "syscall": f.syscall,
                "tier": f.tier,
                "state": f.state,
                "weight": round(f.weight, 4),
                "deduction": round(f.deduction, 4),
            }), file=sys.stderr)

    if args.format == "json":
        print(result.to_json())
    else:
        print(_format_text(result))

    if args.min_score is not None and result.score < args.min_score:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
