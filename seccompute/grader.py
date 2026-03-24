"""Score to letter grade conversion and forced-failure logic."""
from __future__ import annotations

_GRADE_TABLE = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


def compute_grade(score: int) -> str:
    """Convert a numeric score (0-100) to a letter grade."""
    for threshold, letter in _GRADE_TABLE:
        if score >= threshold:
            return letter
    return "F"


def check_forced_failure(
    tier1_syscalls: list[str],
    states: dict[str, str],
    annotation_overrides: set[str],
) -> tuple[bool, list[str]]:
    """Check if forced-failure conditions are met.

    Args:
        tier1_syscalls: List of all T1 syscall names.
        states: Effective state per syscall.
        annotation_overrides: T1 syscalls with valid justification annotations.

    Returns:
        (forced_failure, reasons) tuple.
    """
    reasons: list[str] = []
    for sc in sorted(tier1_syscalls):
        if states.get(sc) == "allowed" and sc not in annotation_overrides:
            reasons.append(f"{sc} allowed unconditionally (T1 catastrophic)")
    return (len(reasons) > 0, reasons)
