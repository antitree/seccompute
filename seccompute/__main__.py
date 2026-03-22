"""CLI entry point for seccompute scoring engine.

Usage:
    python -m seccompute profile.json [--arch ARCH] [--format json|text] [--verbose]

Exit codes:
    0 - Success, no warnings
    1 - Error (file not found, invalid JSON, etc.)
    2 - Success with warnings (unknown syscalls, etc.)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .scoring import ScoringResult, score_profile


def _serialize_result(result: ScoringResult) -> dict:
    """Convert ScoringResult to a JSON-serializable dict."""
    tier_breakdown = {}
    for key, ts in result.tier_breakdown.items():
        tier_breakdown[key] = {
            "tier": ts.tier,
            "budget": ts.budget,
            "total_syscalls": ts.total_syscalls,
            "allowed_count": ts.allowed_count,
            "conditional_count": ts.conditional_count,
            "blocked_count": ts.blocked_count,
            "deduction": round(ts.deduction, 2),
        }

    syscall_details = []
    for sd in result.syscall_details:
        syscall_details.append({
            "name": sd.name,
            "tier": sd.tier,
            "state": sd.state,
            "weight": round(sd.weight, 4),
            "multiplier": sd.multiplier,
            "deduction": round(sd.deduction, 4),
            "is_unknown": sd.is_unknown,
        })

    conditionals = []
    for cn in result.conditionals:
        conditionals.append({
            "syscall": cn.syscall,
            "condition_type": cn.condition_type,
            "multiplier": cn.multiplier,
            "details": cn.details,
            "rule_action": cn.rule_action,
        })

    combo_findings = []
    for cf in result.combo_findings:
        combo_findings.append({
            "id": cf.id,
            "name": cf.name,
            "severity": cf.severity,
            "triggered_by": cf.triggered_by,
            "bypasses_blocked": cf.bypasses_blocked,
            "description": cf.description,
            "references": cf.references,
        })

    # Cap scope analysis (elevated mode only)
    cap_scope_analysis = {}
    if result.scoring_mode == "elevated" and result.granted_caps:
        from .cap_scope import get_scope_for_caps
        primary, related = get_scope_for_caps(result.granted_caps)
        cap_scope_analysis = {
            "in_scope_primary": [sd.name for sd in result.syscall_details if sd.name in primary and sd.state != "blocked"],
            "in_scope_related": [sd.name for sd in result.syscall_details if sd.name in related and sd.state != "blocked"],
            "out_of_scope_dangerous": [sd.name for sd in result.syscall_details if sd.name not in primary and sd.name not in related and sd.state != "blocked" and sd.tier in (1, 2)],
        }

    correctness_out = None
    if result.correctness_score is not None:
        correctness_details_out = [
            {
                "name": cd.name,
                "tier": cd.tier,
                "state": cd.state,
                "weight": round(cd.weight, 4),
                "multiplier": cd.multiplier,
                "deduction": round(cd.deduction, 4),
                "justification": cd.justification,
                "confined": cd.confined,
            }
            for cd in result.correctness_details
            if cd.state != "blocked"
        ]
        correctness_out = {
            "score": result.correctness_score,
            "details": correctness_details_out,
        }

    intent_out = None
    if result.intent:
        intent_out = {
            "description": result.intent.description,
            "syscalls": {
                name: {"justification": si.justification, "confined": si.confined}
                for name, si in result.intent.syscalls.items()
            },
        }

    return {
        "risk_score": result.score,
        "correctness": correctness_out,
        "intent": intent_out,
        "scoring_mode": result.scoring_mode,
        "granted_caps": result.granted_caps,
        "cap_scope_analysis": cap_scope_analysis,
        "tier_breakdown": tier_breakdown,
        "syscall_details": syscall_details,
        "conditionals": conditionals,
        "combo_findings": combo_findings,
        "warnings": result.warnings,
        "metadata": result.metadata,
    }


def _caps_for_syscall(syscall: str, granted_caps: list[str]) -> str:
    """Return which granted caps justify this syscall."""
    from .cap_scope import _load
    scope = _load()
    justifying = []
    for cap in granted_caps:
        entry = scope.get(cap, {})
        if syscall in entry.get("primary", []) or syscall in entry.get("related", []):
            justifying.append(cap)
    return ", ".join(justifying) if justifying else "unknown"


def _format_text(result: ScoringResult) -> str:
    """Format ScoringResult as human-readable text.

    Layout:
      1. Combo bypass visualizations (if any)
      2. Final summary (scores, exposed syscalls count, arch)
    """
    lines = []

    # 1. Combo bypass visualizations at the top
    if result.combo_findings:
        from .viz import render_combo_warning
        for cf in result.combo_findings:
            lines.append(render_combo_warning(cf, style=4))

    # 2. Summary
    if result.scoring_mode == "elevated":
        caps_str = ", ".join(result.granted_caps)
        lines.append(f"Risk Score: {result.score}/100  [ELEVATED MODE: {caps_str}]")
    elif result.correctness_score is not None:
        lines.append(f"Risk Score:        {result.score}/100")
        lines.append(f"Correctness Score: {result.correctness_score}/100")
        if result.intent and result.intent.description:
            lines.append(f"Intent:            {result.intent.description}")
    else:
        lines.append(f"Risk Score: {result.score}/100")

    exposed = [sd for sd in result.syscall_details if sd.state != "blocked"]
    exposed_t1 = [sd for sd in exposed if sd.tier == 1]
    exposed_t2 = [sd for sd in exposed if sd.tier == 2]
    lines.append(f"Exposed:           {len(exposed)} syscalls "
                 f"({len(exposed_t1)} tier-1, {len(exposed_t2)} tier-2)")

    if result.combo_findings:
        lines.append(f"Combo findings:    {len(result.combo_findings)}")

    non_combo_warnings = [w for w in result.warnings if not w.startswith("COMBO ")]
    if non_combo_warnings:
        lines.append("Warnings:")
        for w in non_combo_warnings:
            lines.append(f"  - {w}")

    lines.append(f"Arch: {result.metadata.get('arch', 'unknown')}  "
                 f"Engine: v{result.metadata.get('engine_version', 'unknown')}")

    return "\n".join(lines)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="seccompute",
        description="Score a seccomp profile on a 0-100 hardening scale.",
    )
    parser.add_argument(
        "profile",
        help="Path to OCI seccomp profile JSON file",
    )
    parser.add_argument(
        "--arch",
        default="SCMP_ARCH_X86_64",
        help="Target architecture (default: SCMP_ARCH_X86_64)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--caps",
        default="",
        help="Comma-separated Linux capabilities granted to container (e.g. CAP_SYS_ADMIN,CAP_NET_ADMIN). Enables elevated scoring mode.",
    )
    parser.add_argument(
        "--grade",
        action="store_true",
        help="Show graded visualization with letter grade and tier breakdown",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Detailed per-syscall breakdown to stderr",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactively declare intent for each dangerous syscall finding",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Write scores and intent back into the profile file as x-seccompute block",
    )
    return parser.parse_args(argv)


def _collect_intent_interactive(result) -> "IntentBlock":
    """Walk through dangerous allowed syscalls and collect user justifications."""
    from .intent import IntentBlock, SyscallIntent

    print("\n=== Interactive Intent Declaration ===", file=sys.stderr)
    print("For each dangerous syscall that is allowed, you may provide justification.", file=sys.stderr)
    print("Press Enter to skip any syscall.\n", file=sys.stderr)

    existing = result.intent or IntentBlock()
    description = existing.description

    if not description:
        desc = input("Application description (what does this container do?): ").strip()
        description = desc if desc else ""

    syscalls: dict = dict(existing.syscalls)

    exposed = [sd for sd in result.syscall_details if sd.state != "blocked"]

    for sd in exposed:
        tier_label = f"T{sd.tier}"
        state_label = sd.state.upper()
        print(f"\n[{state_label}] {sd.name} ({tier_label}, risk deduction: {sd.deduction:.2f})", file=sys.stderr)

        existing_intent = syscalls.get(sd.name)
        if existing_intent:
            print(f"  Existing: {existing_intent.justification} (confined={existing_intent.confined})", file=sys.stderr)
            update = input("  Update? [y/N]: ").strip().lower()
            if update != "y":
                continue

        justification = input("  Justification (Enter to skip): ").strip()
        if not justification:
            continue

        confined_input = input("  Confined by arg filters? [y/N]: ").strip().lower()
        confined = confined_input == "y"

        syscalls[sd.name] = SyscallIntent(justification=justification, confined=confined)

    return IntentBlock(description=description, syscalls=syscalls)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Returns:
        Exit code: 0 success, 1 error, 2 warnings.
    """
    args = _parse_args(argv)

    profile_path = Path(args.profile)
    if not profile_path.exists():
        print(f"Error: file not found: {profile_path}", file=sys.stderr)
        return 1

    try:
        with open(profile_path, encoding="utf-8") as f:
            profile = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        return 1

    if not isinstance(profile, dict) or "defaultAction" not in profile:
        print("Error: not a valid OCI seccomp profile (missing defaultAction)", file=sys.stderr)
        return 1

    granted_caps = [c.strip() for c in args.caps.split(",") if c.strip()] if args.caps else None
    result = score_profile(profile, arch=args.arch, granted_caps=granted_caps)

    # Interactive mode: collect intent, recompute with correctness
    profile_for_save = profile
    if args.interactive:
        intent = _collect_intent_interactive(result)
        # Embed intent into profile dict and rescore
        import copy
        profile_with_intent = copy.deepcopy(profile)
        xblock = profile_with_intent.setdefault("x-seccompute", {})
        xblock["intent"] = {
            "description": intent.description,
            "syscalls": {
                name: {"justification": si.justification, "confined": si.confined}
                for name, si in intent.syscalls.items()
            },
        }
        result = score_profile(profile_with_intent, arch=args.arch, intent=intent)
        profile_for_save = profile_with_intent

    if args.save:
        from .intent import save_profile_with_scores
        save_profile_with_scores(
            profile_path, profile_for_save,
            result.score, result.correctness_score,
            result.metadata["engine_version"],
        )
        print(f"Scores saved to {profile_path}", file=sys.stderr)

    if args.grade:
        from .grader import render_grade
        print(render_grade(result, style=4))
        if result.warnings or result.combo_findings:
            return 2
        return 0

    if args.verbose:
        for sd in result.syscall_details:
            if sd.state != "blocked":
                print(
                    json.dumps({
                        "syscall": sd.name,
                        "tier": sd.tier,
                        "state": sd.state,
                        "weight": round(sd.weight, 4),
                        "deduction": round(sd.deduction, 4),
                        "unknown": sd.is_unknown,
                    }),
                    file=sys.stderr,
                )
        for cn in result.conditionals:
            print(
                json.dumps({
                    "conditional": cn.syscall,
                    "type": cn.condition_type,
                    "details": cn.details,
                }),
                file=sys.stderr,
            )

    if args.format == "json":
        output = _serialize_result(result)
        print(json.dumps(output, indent=2))
    else:
        print(_format_text(result))


    if result.warnings or result.combo_findings:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
