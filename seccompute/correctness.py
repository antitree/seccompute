"""Correctness scoring for seccomp profiles.

Correctness score (0-100):
- Allowed syscall WITH justification AND confined (arg-filtered): 0.0x penalty
- Allowed syscall WITH justification but NOT confined: 0.3x penalty
- Allowed syscall with NO justification: 1.0x penalty (same as risk)
- Blocked syscall: 0 penalty
"""
from __future__ import annotations

from dataclasses import dataclass

from .intent import IntentBlock
from .weights_v2 import tier_weight


_JUSTIFIED_CONFINED = 0.0
_JUSTIFIED_UNCONFINED = 0.3
_UNJUSTIFIED = 1.0


@dataclass
class CorrectnessDetail:
    name: str
    tier: int
    state: str
    weight: float
    multiplier: float
    deduction: float
    justification: str
    confined: bool


def compute_correctness(
    syscall_details: list,
    intent: IntentBlock,
) -> tuple[int, list[CorrectnessDetail]]:
    """Compute correctness score given scored syscall details and intent."""
    details: list[CorrectnessDetail] = []
    total_deduction = 0.0

    for sd in syscall_details:
        if sd.state == "blocked":
            details.append(CorrectnessDetail(
                name=sd.name, tier=sd.tier, state=sd.state,
                weight=sd.weight, multiplier=0.0, deduction=0.0,
                justification="", confined=False,
            ))
            continue

        sc_intent = intent.syscalls.get(sd.name)
        if sc_intent and sc_intent.justification:
            multiplier = _JUSTIFIED_CONFINED if sc_intent.confined else _JUSTIFIED_UNCONFINED
            justification = sc_intent.justification
            confined = sc_intent.confined
        else:
            multiplier = _UNJUSTIFIED
            justification = ""
            confined = False

        deduction = sd.weight * multiplier
        total_deduction += deduction
        details.append(CorrectnessDetail(
            name=sd.name, tier=sd.tier, state=sd.state,
            weight=sd.weight, multiplier=multiplier, deduction=deduction,
            justification=justification, confined=confined,
        ))

    score = max(0, min(100, round(100.0 - total_deduction)))
    return score, details
