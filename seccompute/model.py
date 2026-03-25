"""Data model for seccompute scoring results.

All dataclasses used in the public API and internal pipeline.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "1.0"
ENGINE_VERSION = "3.0.0"


@dataclass(frozen=True)
class TierFinding:
    """A finding for a dangerous syscall that is exposed (allowed or conditional)."""
    syscall: str
    tier: int
    state: str  # "allowed" | "conditional" | "blocked"
    weight: float
    deduction: float
    description: str
    exploit_paths: list[str] = field(default_factory=list)
    justification: str | None = None  # from x-seccompute annotation


@dataclass(frozen=True)
class ComboFinding:
    """A triggered combo rule finding."""
    id: str
    name: str
    description: str
    severity: str  # HIGH | MEDIUM | LOW
    triggered_by: list[str]
    bypasses_blocked: list[str]
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ConditionalFinding:
    """Record of a conditional interpretation applied during scoring."""
    syscall: str
    condition_type: str  # capability_gate, argument_filter, etc.
    details: str
    rule_action: str
    resolved: bool | None = None  # None=no caps context, True=granted, False=not granted


@dataclass(frozen=True)
class ScoringResult:
    """Complete scoring result for a seccomp profile."""
    score: int
    grade: str
    forced_failure: bool
    forced_failure_reasons: list[str]
    annotation_overrides: list[str]
    scoring_mode: str
    tier_summary: dict[str, int]
    tier_findings: list[TierFinding]
    combo_findings: list[ComboFinding]
    conditional_findings: list[ConditionalFinding]
    warnings: list[str]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict matching the schema."""
        return {
            "schema_version": SCHEMA_VERSION,
            "score": self.score,
            "grade": self.grade,
            "forced_failure": self.forced_failure,
            "forced_failure_reasons": list(self.forced_failure_reasons),
            "annotation_overrides": list(self.annotation_overrides),
            "scoring_mode": self.scoring_mode,
            "tier_summary": dict(self.tier_summary),
            "tier_findings": [
                {
                    "syscall": f.syscall,
                    "tier": f.tier,
                    "state": f.state,
                    "weight": round(f.weight, 4),
                    "deduction": round(f.deduction, 4),
                    "description": f.description,
                    "exploit_paths": list(f.exploit_paths),
                    **({"justification": f.justification} if f.justification else {}),
                }
                for f in self.tier_findings
            ],
            "combo_findings": [
                {
                    "id": c.id,
                    "name": c.name,
                    "description": c.description,
                    "severity": c.severity,
                    "triggered_by": list(c.triggered_by),
                    "bypasses_blocked": list(c.bypasses_blocked),
                    "references": list(c.references),
                }
                for c in self.combo_findings
            ],
            "conditional_findings": [
                {
                    "syscall": c.syscall,
                    "condition_type": c.condition_type,
                    "details": c.details,
                    "rule_action": c.rule_action,
                    "resolved": c.resolved,
                }
                for c in self.conditional_findings
            ],
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        """Return stable JSON string."""
        return json.dumps(self.to_dict(), indent=2)
