"""Graded summary output for seccompute scoring results.

Renders ScoringResult as a human-readable grade view with letter grades,
color-coded output, and structured problem summaries.

Four rendering styles:
  1. Compact scorecard
  2. Report card
  3. Dashboard / gauge
  4. Report card with tier bar charts
"""

from __future__ import annotations

from .scoring import ScoringResult

# ANSI escape codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_WHITE = "\033[37m"
_BG_RED = "\033[41m"
_BG_GREEN = "\033[42m"
_BG_YELLOW = "\033[43m"
_BG_CYAN = "\033[46m"

# Grade thresholds
_GRADE_TABLE = [
    (90, "A", _GREEN),
    (80, "B", _CYAN),
    (70, "C", _YELLOW),
    (60, "D", _YELLOW),
    (0,  "F", _RED),
]

MAX_PROBLEMS = 5


def _forced_f_warning(grade_dict: dict) -> str | None:
    """Return a forced-F warning line if applicable, else None."""
    if not grade_dict.get("forced_f"):
        return None
    names = ", ".join(grade_dict["forced_f_syscalls"])
    return f"{_BOLD}{_RED}\u26a0  FORCED F: {names} allowed unconditionally (T1){_RESET}"


def compute_grade(result: ScoringResult) -> dict:
    """Compute a weighted grade from the scoring result.

    Since the codebase currently only has a single `score` field (0-100),
    the grade maps directly from that value. If `correctness` and `intent`
    fields are added to ScoringResult in the future, this function should
    be updated to incorporate them with the specified weights (50/30/20).

    Returns:
        Dict with weighted_score, letter, color, and component breakdown.
    """
    score = result.score

    # Future-proof: if correctness/intent are added to ScoringResult
    correctness = getattr(result, "correctness", None)
    intent = getattr(result, "intent", None)

    if correctness is not None and intent is not None:
        # Normalize correctness if it's 0.0-1.0
        c = correctness * 100 if correctness <= 1.0 else correctness
        # Normalize intent if it's 0.0-1.0
        i = intent * 100 if intent <= 1.0 else intent
        weighted = score * 0.5 + c * 0.3 + i * 0.2
    else:
        weighted = float(score)

    letter = "F"
    color = _RED
    for threshold, grade, clr in _GRADE_TABLE:
        if weighted >= threshold:
            letter = grade
            color = clr
            break

    # Detect unconditional T1 allows -> forced F
    forced_f = False
    forced_f_syscalls: list[str] = []

    # x-seccompute acknowledged T1 syscalls lift the forced F
    acknowledged = set(result.metadata.get("x_seccompute_acknowledged_t1", []))

    for sd in result.syscall_details:
        if sd.tier == 1 and sd.state == "allowed" and sd.name not in acknowledged:
            forced_f_syscalls.append(sd.name)

    if forced_f_syscalls:
        forced_f = True
        letter = "F"
        color = _RED

    return {
        "weighted_score": round(weighted, 1),
        "letter": letter,
        "color": color,
        "score": score,
        "correctness": correctness,
        "intent": intent,
        "forced_f": forced_f,
        "forced_f_syscalls": forced_f_syscalls,
    }


def _get_problems(result: ScoringResult) -> dict:
    """Extract categorized problems from a ScoringResult."""
    # Combo warnings
    combos = []
    for cf in result.combo_findings:
        combos.append(f"[{cf.severity}] {cf.name}: {', '.join(cf.triggered_by)}")

    # Allowed dangerous syscalls (tier 1 and 2 only for brevity)
    dangerous = []
    for sd in result.syscall_details:
        if sd.state == "allowed" and sd.tier in (1, 2):
            dangerous.append(f"T{sd.tier} {sd.name} (weight {sd.weight:.1f})")

    # Conditional dangerous syscalls
    conditional = []
    for sd in result.syscall_details:
        if sd.state == "conditional" and sd.tier in (1, 2):
            conditional.append(f"T{sd.tier} {sd.name} (conditional)")

    return {
        "combos": combos,
        "dangerous_allowed": dangerous,
        "conditional": conditional,
    }


def _truncated_list(items: list[str], max_items: int = MAX_PROBLEMS) -> list[str]:
    """Return items truncated with a count suffix if needed."""
    if len(items) <= max_items:
        return items
    remaining = len(items) - max_items
    return items[:max_items] + [f"+ {remaining} more"]


def _tier_summary(result: ScoringResult) -> list[str]:
    """One-line summary per tier."""
    lines = []
    for key in ("tier1", "tier2", "tier3"):
        ts = result.tier_breakdown[key]
        lines.append(
            f"T{ts.tier}: {ts.blocked_count}B {ts.conditional_count}C "
            f"{ts.allowed_count}A  (-{ts.deduction:.0f}pts)"
        )
    return lines


# ---------------------------------------------------------------------------
# Style 1: Compact Scorecard
# ---------------------------------------------------------------------------

def render_grade_v1(result: ScoringResult) -> str:
    """Compact scorecard with large grade letter and key metrics."""
    g = compute_grade(result)
    problems = _get_problems(result)
    tiers = _tier_summary(result)

    letter = g["letter"]
    color = g["color"]
    score = g["weighted_score"]

    lines = []
    lines.append("")
    lines.append(f"{_BOLD}{color}  {'=' * 50}{_RESET}")
    lines.append(f"{_BOLD}{color}   SECCOMPUTE HARDENING GRADE{_RESET}")
    lines.append(f"{_BOLD}{color}  {'=' * 50}{_RESET}")
    lines.append("")

    # Large letter grade block
    _letter_art = {
        "A": ["  ####  ", " #    # ", " ###### ", " #    # ", " #    # "],
        "B": [" #####  ", " #    # ", " #####  ", " #    # ", " #####  "],
        "C": ["  ####  ", " #      ", " #      ", " #      ", "  ####  "],
        "D": [" #####  ", " #    # ", " #    # ", " #    # ", " #####  "],
        "F": [" ###### ", " #      ", " ####   ", " #      ", " #      "],
    }

    art = _letter_art.get(letter, _letter_art["F"])
    for i, art_line in enumerate(art):
        if i == 1:
            right = f"  Score: {score:.0f}/100"
        elif i == 2:
            mode = result.scoring_mode.upper()
            right = f"  Mode:  {mode}"
        elif i == 3:
            right = f"  Engine: v{result.metadata.get('engine_version', '?')}"
        else:
            right = ""
        lines.append(f"   {color}{_BOLD}{art_line}{_RESET}{right}")

    lines.append("")

    # Forced F warning
    ff_warn = _forced_f_warning(g)
    if ff_warn:
        lines.append(f"   {ff_warn}")
        lines.append("")

    # Tier breakdown
    lines.append(f"   {_BOLD}Tier Breakdown{_RESET}")
    lines.append(f"   {_DIM}{'- ' * 25}{_RESET}")
    for t in tiers:
        lines.append(f"   {t}")
    lines.append("")

    # Problems
    has_problems = any(problems.values())
    if has_problems:
        lines.append(f"   {_BOLD}{_RED}Problems{_RESET}")
        lines.append(f"   {_DIM}{'- ' * 25}{_RESET}")

        if problems["combos"]:
            lines.append(f"   {_YELLOW}Combo Risks:{_RESET}")
            for p in _truncated_list(problems["combos"]):
                lines.append(f"     {p}")

        if problems["dangerous_allowed"]:
            lines.append(f"   {_RED}Dangerous Allowed:{_RESET}")
            for p in _truncated_list(problems["dangerous_allowed"]):
                lines.append(f"     {p}")

        if problems["conditional"]:
            lines.append(f"   {_YELLOW}Conditional (risky):{_RESET}")
            for p in _truncated_list(problems["conditional"]):
                lines.append(f"     {p}")
    else:
        lines.append(f"   {_GREEN}No critical problems detected.{_RESET}")

    lines.append("")
    lines.append(f"{_BOLD}{color}  {'=' * 50}{_RESET}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Style 2: Report Card
# ---------------------------------------------------------------------------

def render_grade_v2(result: ScoringResult) -> str:
    """Report card layout with ruled lines and subject rows."""
    g = compute_grade(result)
    problems = _get_problems(result)

    color = g["color"]
    letter = g["letter"]
    score = g["weighted_score"]

    w = 56  # total width

    lines = []
    lines.append("")
    lines.append(f"   {'_' * w}")
    lines.append(f"  |{'':^{w}}|")
    lines.append(f"  |{_BOLD}{'SECCOMP PROFILE REPORT CARD':^{w}}{_RESET}|")
    lines.append(f"  |{'_' * w}|")
    lines.append(f"  |{'':^{w}}|")

    # Subject rows
    subjects = [
        ("Tier 1 (Catastrophic)", result.tier_breakdown["tier1"]),
        ("Tier 2 (Serious)",      result.tier_breakdown["tier2"]),
        ("Tier 3 (Elevated)",     result.tier_breakdown["tier3"]),
    ]

    header = f"  | {'Subject':<26} {'Blocked':>7} {'Cond':>5} {'Allow':>5} {'Ded':>6} |"
    lines.append(header)
    lines.append(f"  |{'-' * w}|")

    for name, ts in subjects:
        ded_str = f"-{ts.deduction:.0f}"
        row = f"  | {name:<26} {ts.blocked_count:>7} {ts.conditional_count:>5} {ts.allowed_count:>5} {ded_str:>6} |"
        lines.append(row)

    lines.append(f"  |{'-' * w}|")

    # Combos row
    combo_count = len(result.combo_findings)
    combo_color = _RED if combo_count > 0 else _GREEN
    combo_label = f"{combo_count} combo finding(s)"
    lines.append(f"  | {'Combo Risks':<26} {combo_color}{combo_label:>25}{_RESET}      |")
    lines.append(f"  |{'_' * w}|")
    lines.append(f"  |{'':^{w}}|")

    # Final grade
    grade_line = f"FINAL GRADE:  {letter}  ({score:.0f}/100)"
    lines.append(f"  |{color}{_BOLD}{grade_line:^{w}}{_RESET}|")
    lines.append(f"  |{'_' * w}|")

    # Forced F warning (outside box)
    ff_warn = _forced_f_warning(g)
    if ff_warn:
        lines.append("")
        lines.append(f"   {ff_warn}")

    # Problems footer
    lines.append("")
    has_problems = any(problems.values())
    if has_problems:
        lines.append(f"   {_BOLD}Notes:{_RESET}")
        all_problems = (
            problems["combos"]
            + problems["dangerous_allowed"]
            + problems["conditional"]
        )
        for p in _truncated_list(all_problems):
            lines.append(f"   - {p}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Style 3: Dashboard / Gauge
# ---------------------------------------------------------------------------

def render_grade_v3(result: ScoringResult) -> str:
    """Dashboard with ASCII gauge meter and problems panel."""
    g = compute_grade(result)
    problems = _get_problems(result)

    color = g["color"]
    letter = g["letter"]
    score = g["weighted_score"]

    lines = []
    lines.append("")
    lines.append(f"   {_BOLD}SECCOMPUTE DASHBOARD{_RESET}")
    lines.append(f"   {_DIM}{'=' * 48}{_RESET}")
    lines.append("")

    # ASCII gauge (0-100 mapped to 40 chars)
    gauge_width = 40
    filled = int(score / 100 * gauge_width)
    filled = max(0, min(gauge_width, filled))
    empty = gauge_width - filled

    bar = f"{'#' * filled}{'.' * empty}"
    lines.append(f"   0   {color}{_BOLD}{bar}{_RESET}   100")
    lines.append(f"       {' ' * (filled - 1)}{_BOLD}{color}^{_RESET}")
    lines.append(f"       {' ' * max(0, filled - 3)}{color}{_BOLD}{score:.0f} ({letter}){_RESET}")
    lines.append("")

    # Forced F warning
    ff_warn = _forced_f_warning(g)
    if ff_warn:
        lines.append(f"   {ff_warn}")
        lines.append("")

    # Metric cards
    lines.append(f"   {_BOLD}Metrics{_RESET}")
    lines.append(f"   {'-' * 48}")

    for key in ("tier1", "tier2", "tier3"):
        ts = result.tier_breakdown[key]
        pct = ((ts.budget - ts.deduction) / ts.budget * 100) if ts.budget else 0
        mini_bar_len = 20
        mini_filled = int(pct / 100 * mini_bar_len)
        mini_bar = f"{'|' * mini_filled}{'.' * (mini_bar_len - mini_filled)}"

        tier_color = _GREEN if pct >= 80 else (_YELLOW if pct >= 50 else _RED)
        lines.append(
            f"   T{ts.tier} [{tier_color}{mini_bar}{_RESET}] "
            f"{pct:5.0f}%  ({ts.budget - ts.deduction:.0f}/{ts.budget:.0f}pts)"
        )

    lines.append("")

    # Problems panel
    lines.append(f"   {_BOLD}Problems{_RESET}")
    lines.append(f"   {'-' * 48}")

    has_problems = any(problems.values())
    if not has_problems:
        lines.append(f"   {_GREEN}None - profile looks solid.{_RESET}")
    else:
        if problems["combos"]:
            for p in _truncated_list(problems["combos"]):
                lines.append(f"   {_YELLOW}! {p}{_RESET}")
        if problems["dangerous_allowed"]:
            for p in _truncated_list(problems["dangerous_allowed"]):
                lines.append(f"   {_RED}x {p}{_RESET}")
        if problems["conditional"]:
            for p in _truncated_list(problems["conditional"]):
                lines.append(f"   {_YELLOW}~ {p}{_RESET}")

    lines.append("")
    lines.append(f"   {_DIM}Engine v{result.metadata.get('engine_version', '?')} | "
                 f"Arch: {result.metadata.get('arch', '?')} | "
                 f"Mode: {result.scoring_mode}{_RESET}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Style 4: Report Card with Tier Bar Charts
# ---------------------------------------------------------------------------

def render_grade_v4(result: ScoringResult) -> str:
    """Report card with per-tier mini bar charts and bordered layout."""
    g = compute_grade(result)
    problems = _get_problems(result)

    color = g["color"]
    letter = g["letter"]
    score = g["weighted_score"]

    w = 56  # total width

    lines = []
    lines.append("")
    lines.append(f"   {'_' * w}")
    lines.append(f"  |{'':^{w}}|")
    lines.append(f"  |{_BOLD}{'SECCOMP PROFILE REPORT CARD':^{w}}{_RESET}|")
    lines.append(f"  |{'_' * w}|")
    lines.append(f"  |{'':^{w}}|")

    # Metrics header
    lines.append(f"  | {_BOLD}{'Metrics'}{_RESET}{' ' * (w - 9)}|")
    lines.append(f"  |{'-' * w}|")

    # Per-tier bar charts
    for key in ("tier1", "tier2", "tier3"):
        ts = result.tier_breakdown[key]
        pct = ((ts.budget - ts.deduction) / ts.budget * 100) if ts.budget else 0
        mini_bar_len = 20
        mini_filled = int(pct / 100 * mini_bar_len)
        mini_bar = f"{'|' * mini_filled}{'.' * (mini_bar_len - mini_filled)}"

        tier_color = _GREEN if pct >= 80 else (_YELLOW if pct >= 50 else _RED)
        earned = ts.budget - ts.deduction
        content = (
            f" T{ts.tier} [{tier_color}{mini_bar}{_RESET}] "
            f"{pct:5.0f}%  ({earned:.0f}/{ts.budget:.0f}pts)"
        )
        # Pad to width (accounting for ANSI codes not taking visual space)
        visible_len = len(f" T{ts.tier} [{mini_bar}] {pct:5.0f}%  ({earned:.0f}/{ts.budget:.0f}pts)")
        pad = w - visible_len
        lines.append(f"  |{content}{' ' * pad}|")

    lines.append(f"  |{'-' * w}|")

    # Combos row
    combo_count = len(result.combo_findings)
    combo_color = _RED if combo_count > 0 else _GREEN
    combo_label = f"{combo_count} combo finding(s)"
    lines.append(f"  | {'Combo Risks':<26} {combo_color}{combo_label:>25}{_RESET}      |")
    lines.append(f"  |{'_' * w}|")
    lines.append(f"  |{'':^{w}}|")

    # Final grade
    grade_line = f"FINAL GRADE:  {letter}  ({score:.0f}/100)"
    lines.append(f"  |{color}{_BOLD}{grade_line:^{w}}{_RESET}|")
    lines.append(f"  |{'_' * w}|")

    # Forced F warning (outside box)
    ff_warn = _forced_f_warning(g)
    if ff_warn:
        lines.append("")
        lines.append(f"   {ff_warn}")

    # Problems footer
    lines.append("")
    has_problems = any(problems.values())
    if has_problems:
        lines.append(f"   {_BOLD}Notes:{_RESET}")
        all_problems = (
            problems["combos"]
            + problems["dangerous_allowed"]
            + problems["conditional"]
        )
        for p in _truncated_list(all_problems):
            lines.append(f"   - {p}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def render_grade(result: ScoringResult, style: int = 1) -> str:
    """Render a graded summary of a ScoringResult.

    Args:
        result: The scoring result to render.
        style: Rendering style (1=compact, 2=report card, 3=dashboard, 4=report+bars).

    Returns:
        Formatted string with ANSI color codes.
    """
    renderers = {1: render_grade_v1, 2: render_grade_v2, 3: render_grade_v3, 4: render_grade_v4}
    renderer = renderers.get(style, render_grade_v1)
    return renderer(result)
