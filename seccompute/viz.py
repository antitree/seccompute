"""Terminal visualization for seccompute results.

Operates solely on ScoringResult objects. Lazy-import only.
"""
from __future__ import annotations

from typing import Protocol

from .model import ScoringResult, ComboFinding

# ANSI codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"

_GRADE_COLORS = {
    "A": _GREEN, "B": _CYAN, "C": _YELLOW, "D": _YELLOW, "F": _RED,
}


class Renderer(Protocol):
    """Protocol for result renderers. Extension point for HTML/SVG/PNG."""
    def render(self, result: ScoringResult) -> str: ...


class TerminalRenderer:
    """Default terminal renderer with ANSI color output."""

    def render(self, result: ScoringResult) -> str:
        color = _GRADE_COLORS.get(result.grade, _RED)
        lines: list[str] = []

        lines.append("")
        lines.append(f"  {_BOLD}{color}{'=' * 50}{_RESET}")
        lines.append(f"  {_BOLD}{color}  SECCOMPUTE HARDENING GRADE{_RESET}")
        lines.append(f"  {_BOLD}{color}{'=' * 50}{_RESET}")
        lines.append("")
        lines.append(f"  {_BOLD}{color}  Grade: {result.grade}   Score: {result.score}/100{_RESET}")
        lines.append("")

        if result.forced_failure:
            for reason in result.forced_failure_reasons:
                lines.append(f"  {_BOLD}{_RED}  FORCED F: {reason}{_RESET}")
            if result.annotation_overrides:
                lines.append(f"  {_DIM}  Overridden: {', '.join(result.annotation_overrides)}{_RESET}")
            lines.append("")

        # Tier summary
        ts = result.tier_summary
        lines.append(f"  {_BOLD}  Tier Summary{_RESET}")
        lines.append(f"  {_DIM}  {'- ' * 25}{_RESET}")
        lines.append(f"    T1 exposed: {ts['t1_exposed']}  T2 exposed: {ts['t2_exposed']}  T3 exposed: {ts['t3_exposed']}")
        lines.append("")

        # Combo findings
        if result.combo_findings:
            lines.append(f"  {_BOLD}{_YELLOW}  Combo Risks ({len(result.combo_findings)}){_RESET}")
            for cf in result.combo_findings:
                lines.append(f"    [{cf.severity}] {cf.name}: {', '.join(cf.triggered_by)}")
            lines.append("")

        # Top tier findings
        exposed = [f for f in result.tier_findings if f.state != "blocked"]
        if exposed:
            lines.append(f"  {_BOLD}{_RED}  Exposed Syscalls{_RESET}")
            for f in exposed[:10]:
                lines.append(f"    T{f.tier} {f.syscall} ({f.state}, -{f.deduction:.1f}pts)")
            if len(exposed) > 10:
                lines.append(f"    + {len(exposed) - 10} more")
            lines.append("")

        if result.warnings:
            lines.append(f"  {_BOLD}  Warnings{_RESET}")
            for w in result.warnings[:5]:
                lines.append(f"    - {w}")
            lines.append("")

        lines.append(f"  {_DIM}  Engine v{result.metadata.get('engine_version', '?')} | "
                     f"Arch: {result.metadata.get('arch', '?')}{_RESET}")
        lines.append(f"  {_BOLD}{color}{'=' * 50}{_RESET}")
        lines.append("")
        return "\n".join(lines)


def render_grade(result: ScoringResult) -> str:
    """Render a graded terminal summary of a ScoringResult."""
    return TerminalRenderer().render(result)
