"""Input format normalizer and validator for seccompute.

Converts OCI seccomp JSON and Kubernetes Security Profiles Operator CRD
into a common internal representation (OCI JSON structure), then validates
the normalized form before scoring.
"""
from __future__ import annotations

import re
from typing import Any

# Syscall names: lowercase letters, digits, underscores, 1-64 chars.
# Covers all known Linux syscall names including arch aliases like
# mmap2, fstat64, etc. Does NOT allow dots — arch prefixes (I386., x32.)
# are stripped by scoring.py before names reach validation.
_SYSCALL_NAME_RE = re.compile(r'^[a-z0-9_]{1,64}$')

# Valid SCMP_ACT_* action strings (complete list from libseccomp).
_VALID_ACTIONS: frozenset[str] = frozenset([
    "SCMP_ACT_KILL",
    "SCMP_ACT_KILL_PROCESS",
    "SCMP_ACT_KILL_THREAD",
    "SCMP_ACT_TRAP",
    "SCMP_ACT_ERRNO",
    "SCMP_ACT_TRACE",
    "SCMP_ACT_LOG",
    "SCMP_ACT_ALLOW",
    "SCMP_ACT_NOTIFY",
])


def _is_k8s_crd(data: dict[str, Any]) -> bool:
    """Detect Kubernetes SeccompProfile CRD."""
    if data.get("kind") == "SeccompProfile":
        return True
    api = data.get("apiVersion", "")
    if isinstance(api, str) and "security-profiles-operator" in api:
        return True
    return False


def _is_oci_profile(data: dict[str, Any]) -> bool:
    """Detect OCI seccomp JSON profile."""
    return "defaultAction" in data and isinstance(data.get("syscalls", []), list)


def _normalize_k8s(data: dict[str, Any]) -> dict[str, Any]:
    """Convert K8s CRD to OCI format."""
    spec = data.get("spec", data)
    result: dict[str, Any] = {
        "defaultAction": spec.get("defaultAction", "SCMP_ACT_ERRNO"),
    }
    if "architectures" in spec:
        result["architectures"] = spec["architectures"]
    if "syscalls" in spec:
        result["syscalls"] = spec["syscalls"]
    else:
        result["syscalls"] = []

    # Preserve x-seccompute annotations from metadata or top-level
    x_sec = data.get("x-seccompute") or spec.get("x-seccompute")
    metadata = data.get("metadata", {})
    if isinstance(metadata, dict):
        annotations = metadata.get("annotations", {})
        if isinstance(annotations, dict) and "x-seccompute" in annotations:
            x_sec = annotations["x-seccompute"]
    if x_sec:
        result["x-seccompute"] = x_sec

    return result


def normalize(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize a profile dict to OCI format.

    Auto-detects format (K8s CRD or OCI JSON) and converts accordingly.
    Raises ValueError on unrecognizable input.
    """
    if not isinstance(data, dict):
        raise ValueError(f"Profile must be a dict, got {type(data).__name__}")

    if _is_k8s_crd(data):
        return _normalize_k8s(data)

    if _is_oci_profile(data):
        return data

    # Try treating as a CRD with spec containing defaultAction
    spec = data.get("spec", {})
    if isinstance(spec, dict) and "defaultAction" in spec:
        return _normalize_k8s(data)

    raise ValueError(
        "Unrecognizable profile format. Expected OCI seccomp JSON "
        "(with 'defaultAction') or Kubernetes SeccompProfile CRD "
        "(with 'kind: SeccompProfile')."
    )


def _is_valid_action(action: str) -> bool:
    """Return True if action is a recognized SCMP_ACT_* value.

    Accepts SCMP_ACT_ERRNO(N) with an errno code suffix (e.g. SCMP_ACT_ERRNO(1)).
    """
    if action in _VALID_ACTIONS:
        return True
    # SCMP_ACT_ERRNO(N) and SCMP_ACT_TRACE(N) carry a numeric argument
    if re.match(r'^SCMP_ACT_(ERRNO|TRACE)\(\d+\)$', action):
        return True
    return False


def validate(profile: dict[str, Any]) -> list[str]:
    """Validate a normalized OCI seccomp profile.

    Returns a list of validation warnings (non-fatal). Raises ValueError
    on fatal structural problems that would make scoring meaningless.

    Checks:
    - defaultAction is a recognized SCMP_ACT_* value
    - syscall rule actions are recognized SCMP_ACT_* values
    - syscall names match ^[a-z0-9_]{1,64}$  (invalid names are warned, not fatal)
    - syscalls list entries are dicts with 'names' list and 'action' string

    Does NOT reject unknown syscall names — those are handled by the scorer
    with conservative T2 weighting. This validator only rejects names that
    could not possibly be real syscalls (control chars, HTML, whitespace, etc.).
    """
    warnings: list[str] = []

    # --- defaultAction ---
    default_action = profile.get("defaultAction", "")
    if not isinstance(default_action, str) or not _is_valid_action(default_action):
        raise ValueError(
            f"Invalid defaultAction: {default_action!r}. "
            f"Must be one of: {', '.join(sorted(_VALID_ACTIONS))}."
        )

    # --- syscalls list ---
    syscalls = profile.get("syscalls", [])
    if not isinstance(syscalls, list):
        raise ValueError(f"'syscalls' must be a list, got {type(syscalls).__name__}")

    for i, rule in enumerate(syscalls):
        if not isinstance(rule, dict):
            warnings.append(f"syscalls[{i}]: expected dict, got {type(rule).__name__} — skipped")
            continue

        # action
        action = rule.get("action", "")
        if not isinstance(action, str) or not _is_valid_action(action):
            warnings.append(
                f"syscalls[{i}]: invalid action {action!r} — rule skipped by scorer"
            )

        # names
        names = rule.get("names", [])
        if not isinstance(names, list):
            warnings.append(f"syscalls[{i}]: 'names' must be a list — rule skipped by scorer")
            continue

        for name in names:
            if not isinstance(name, str):
                warnings.append(f"syscalls[{i}]: syscall name {name!r} is not a string — ignored")
                continue
            # Strip arch prefix before validating the base name
            base = name
            for prefix in ("I386.x32.", "I386.", "x32."):
                if name.startswith(prefix):
                    base = name[len(prefix):]
                    break
            if not _SYSCALL_NAME_RE.match(base):
                warnings.append(
                    f"syscalls[{i}]: suspicious syscall name {name!r} "
                    f"(contains unexpected characters) — scored as unknown"
                )

    return warnings
