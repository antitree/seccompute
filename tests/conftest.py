"""Shared test fixtures and helpers."""
from __future__ import annotations


def make_profile(default_action="SCMP_ACT_ERRNO", rules=None, x_seccompute=None):
    """Build an OCI seccomp profile dict."""
    p = {"defaultAction": default_action, "syscalls": rules or []}
    if x_seccompute is not None:
        p["x-seccompute"] = x_seccompute
    return p


def allow_rule(*names, args=None, includes=None, excludes=None):
    """Build an ALLOW rule."""
    r = {"names": list(names), "action": "SCMP_ACT_ALLOW"}
    if args:
        r["args"] = args
    if includes:
        r["includes"] = includes
    if excludes:
        r["excludes"] = excludes
    return r


def block_rule(*names):
    """Build an ERRNO rule."""
    return {"names": list(names), "action": "SCMP_ACT_ERRNO"}
