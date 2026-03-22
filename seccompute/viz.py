"""Combo finding visualization for terminal output.

Three distinct styles for rendering ComboFinding warnings:
  1. Attack chain (flow-chart with arrows)
  2. Hacker terminal (matrix aesthetic with box-drawing)
  3. Security report card (structured alert)

All styles use ANSI escape codes for color. No external dependencies.
"""

from __future__ import annotations

from .combos import ComboFinding

# ANSI color helpers
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_WHITE = "\033[37m"
_BG_RED = "\033[41m"
_RED_BOLD = f"\033[1;31m"
_YELLOW_BOLD = f"\033[1;33m"
_CYAN_BOLD = f"\033[1;36m"
_GREEN_BOLD = f"\033[1;32m"
_WHITE_BOLD = f"\033[1;37m"
_MAGENTA = "\033[35m"
_MAGENTA_BOLD = f"\033[1;35m"

_SEVERITY_COLOR = {
    "HIGH": _RED_BOLD,
    "MEDIUM": _YELLOW_BOLD,
    "LOW": _WHITE_BOLD,
}


def _sev_color(severity: str) -> str:
    return _SEVERITY_COLOR.get(severity.upper(), _WHITE_BOLD)


def _wrap(text: str, width: int) -> list[str]:
    """Simple word-wrap to given width."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for w in words:
        if current and len(current) + 1 + len(w) > width:
            lines.append(current)
            current = w
        else:
            current = f"{current} {w}" if current else w
    if current:
        lines.append(current)
    return lines or [""]


def render_combo_warning_v1(combo: ComboFinding) -> str:
    """Style 1: Attack chain / flow-chart with arrows.

    Shows the attack path as a left-to-right flow:
    trigger syscalls --> bypass mechanism --> bypassed syscalls
    """
    sc = _sev_color(combo.severity)
    lines: list[str] = []

    # Header
    lines.append("")
    lines.append(f"  {sc}>>> ATTACK CHAIN DETECTED <<<{_RESET}")
    lines.append(f"  {_WHITE_BOLD}{combo.name}{_RESET}  {sc}[{combo.severity}]{_RESET}  {_DIM}{combo.id}{_RESET}")
    lines.append("")

    # Attack flow
    triggers = combo.triggered_by
    bypassed = combo.bypasses_blocked

    # Trigger syscalls
    lines.append(f"  {_GREEN_BOLD}ALLOWED{_RESET}              {_RED_BOLD}BYPASSES{_RESET}                  {_RED_BOLD}BLOCKED (defeated){_RESET}")
    lines.append(f"  {_DIM}{'─' * 20}{'─' * 4}{'─' * 20}{'─' * 4}{'─' * 24}{_RESET}")

    max_rows = max(len(triggers), len(bypassed), 1)
    for i in range(max_rows):
        left = f"  {_GREEN}{triggers[i]}{_RESET}" if i < len(triggers) else "  "
        left = left.ljust(32 + len(_GREEN) + len(_RESET))

        arrow = f" {_YELLOW}--->{_RESET} " if i == 0 else "      "

        right = f"{_RED}{bypassed[i]}{_RESET}" if i < len(bypassed) else ""

        lines.append(f"{left}{arrow}{right}")

    lines.append("")

    # Description
    desc_lines = _wrap(combo.description, 72)
    lines.append(f"  {_DIM}Attacker gains:{_RESET}")
    for dl in desc_lines:
        lines.append(f"  {_DIM}{dl}{_RESET}")

    # References
    if combo.references:
        lines.append(f"  {_DIM}Refs: {', '.join(combo.references)}{_RESET}")

    lines.append("")
    return "\n".join(lines)


def render_combo_warning_v2(combo: ComboFinding) -> str:
    """Style 2: Hacker terminal / matrix aesthetic with box-drawing."""
    sc = _sev_color(combo.severity)
    lines: list[str] = []

    inner_w = 68

    def hline(left: str, fill: str, right: str) -> str:
        return f"  {sc}{left}{fill * inner_w}{right}{_RESET}"

    def row(content: str, pad: int = inner_w) -> str:
        # Strip ANSI for length calc
        import re
        visible = re.sub(r"\033\[[0-9;]*m", "", content)
        padding = pad - len(visible)
        if padding < 0:
            padding = 0
        return f"  {sc}\u2502{_RESET} {content}{' ' * padding}{sc}\u2502{_RESET}"

    lines.append("")
    lines.append(hline("\u250c", "\u2500", "\u2510"))

    # Title bar
    sev_tag = f"[{combo.severity}]"
    title = f"{_WHITE_BOLD}{combo.name}{_RESET}"
    lines.append(row(f" {sc}{sev_tag}{_RESET}  {title}  {_DIM}{combo.id}{_RESET}"))
    lines.append(hline("\u251c", "\u2500", "\u2524"))

    # Trigger section
    lines.append(row(f" {_GREEN_BOLD}TRIGGER SYSCALLS:{_RESET}"))
    for sc_name in combo.triggered_by:
        lines.append(row(f"   {_GREEN}> {sc_name}{_RESET}"))

    lines.append(row(""))

    # Bypass arrow
    lines.append(row(f"        {_YELLOW_BOLD}\u2193\u2193\u2193  seccomp filter bypassed  \u2193\u2193\u2193{_RESET}"))
    lines.append(row(""))

    # Bypassed syscalls
    lines.append(row(f" {_RED_BOLD}BLOCKED SYSCALLS NOW REACHABLE:{_RESET}"))
    # Show in columns of 3
    bypassed = combo.bypasses_blocked
    for i in range(0, len(bypassed), 3):
        chunk = bypassed[i:i+3]
        cell_text = "   ".join(f"{_RED}{s}{_RESET}" for s in chunk)
        lines.append(row(f"   {cell_text}"))

    lines.append(hline("\u251c", "\u2500", "\u2524"))

    # Description
    desc_lines = _wrap(combo.description, inner_w - 2)
    for dl in desc_lines:
        lines.append(row(f" {_DIM}{dl}{_RESET}"))

    # References
    if combo.references:
        lines.append(row(""))
        refs = " ".join(combo.references)
        lines.append(row(f" {_MAGENTA}{refs}{_RESET}"))

    lines.append(hline("\u2514", "\u2500", "\u2518"))
    lines.append("")
    return "\n".join(lines)


def render_combo_warning_v3(combo: ComboFinding) -> str:
    """Style 3: Security report / structured alert card."""
    sc = _sev_color(combo.severity)
    lines: list[str] = []

    sev_upper = combo.severity.upper()
    if sev_upper == "HIGH":
        icon = "\u2622"  # radioactive
        bg = _BG_RED
    elif sev_upper == "MEDIUM":
        icon = "\u26a0"  # warning
        bg = ""
    else:
        icon = "\u2139"  # info
        bg = ""

    lines.append("")
    lines.append(f"  {bg}{_WHITE_BOLD} {icon}  SECCOMP BYPASS ADVISORY  {icon} {_RESET}")
    lines.append("")
    lines.append(f"  {_WHITE_BOLD}Finding:{_RESET}    {combo.name}")
    lines.append(f"  {_WHITE_BOLD}ID:{_RESET}         {combo.id}")
    lines.append(f"  {_WHITE_BOLD}Severity:{_RESET}   {sc}{combo.severity}{_RESET}")
    lines.append("")

    lines.append(f"  {_WHITE_BOLD}Attack Vector:{_RESET}")
    lines.append(f"    Allowed syscalls:  {_GREEN}{', '.join(combo.triggered_by)}{_RESET}")
    lines.append(f"    Defeated blocks:   {_RED}{', '.join(combo.bypasses_blocked)}{_RESET}")
    lines.append("")

    lines.append(f"  {_WHITE_BOLD}Impact:{_RESET}")
    desc_lines = _wrap(combo.description, 66)
    for dl in desc_lines:
        lines.append(f"    {dl}")
    lines.append("")

    if combo.references:
        lines.append(f"  {_WHITE_BOLD}References:{_RESET}")
        for ref in combo.references:
            lines.append(f"    - {_CYAN}{ref}{_RESET}")
        lines.append("")

    lines.append(f"  {_WHITE_BOLD}Recommendation:{_RESET}")
    trigger_str = " and ".join(combo.triggered_by)
    lines.append(f"    Block {_YELLOW}{trigger_str}{_RESET} to eliminate this bypass path.")
    lines.append(f"  {'_' * 60}")
    lines.append("")
    return "\n".join(lines)


def render_combo_warning_v4(combo: ComboFinding) -> str:
    """Style 4: Merged style — bordered box with columns, attack vector, recommendation."""
    import re

    sc = _sev_color(combo.severity)
    lines: list[str] = []

    inner_w = 76  # 80 - 2 for border chars - 2 for outer padding

    def _visible_len(s: str) -> int:
        return len(re.sub(r"\033\[[0-9;]*m", "", s))

    def hline(left: str, fill: str, right: str) -> str:
        return f"{sc}{left}{fill * inner_w}{right}{_RESET}"

    def row(content: str) -> str:
        vis = _visible_len(content)
        pad = inner_w - vis - 1  # -1 for leading space
        if pad < 0:
            pad = 0
        return f"{sc}\u2502{_RESET} {content}{' ' * pad}{sc}\u2502{_RESET}"

    # Top border
    lines.append(hline("\u250c", "\u2500", "\u2510"))

    # Title
    sev_tag = f"{sc}[{combo.severity}]{_RESET}"
    title = f"{_WHITE_BOLD}{combo.name}{_RESET}"
    lines.append(row(f"{sev_tag}  {title}  {_DIM}{combo.id}{_RESET}"))
    lines.append(hline("\u251c", "\u2500", "\u2524"))

    # Column headers
    col_left_w = 24
    arrow_w = 5
    lines.append(row(
        f"{_WHITE_BOLD}{'ALLOWED':<{col_left_w}}{_RESET}"
        f"{' ' * arrow_w}"
        f"{_WHITE_BOLD}BYPASSES{_RESET}"
    ))

    # Column rows
    triggers = combo.triggered_by
    bypassed = combo.bypasses_blocked
    max_rows = max(len(triggers), len(bypassed), 1)
    for i in range(max_rows):
        left_val = triggers[i] if i < len(triggers) else ""
        right_val = bypassed[i] if i < len(bypassed) else ""

        left_str = f"{_GREEN}{left_val}{_RESET}" if left_val else ""
        left_pad = col_left_w - len(left_val)
        if left_pad < 0:
            left_pad = 0

        arrow = f"{_YELLOW}\u2192{_RESET}"
        right_str = f"{_RED}{right_val}{_RESET}" if right_val else ""

        lines.append(row(
            f"{left_str}{' ' * left_pad}"
            f"  {arrow}  "
            f"{right_str}"
        ))

    lines.append(hline("\u251c", "\u2500", "\u2524"))

    # Attack Vector
    lines.append(row(f"{_RED_BOLD}Attack Vector:{_RESET}"))
    desc_lines = _wrap(combo.description, inner_w - 4)
    for dl in desc_lines:
        lines.append(row(f"  {_DIM}{dl}{_RESET}"))

    if combo.references:
        refs = ", ".join(combo.references)
        lines.append(row(f"  {_MAGENTA}{refs}{_RESET}"))

    lines.append(hline("\u251c", "\u2500", "\u2524"))

    # Recommendation
    lines.append(row(f"{_GREEN_BOLD}Recommendation:{_RESET}"))
    trigger_str = ", ".join(combo.triggered_by)
    lines.append(row(f"  1. Add {_YELLOW}{trigger_str}{_RESET} to your blocked syscalls list"))
    lines.append(row(f"  2. Re-score with: {_CYAN}seccompute profile.json{_RESET}"))
    bypassed_count = len(combo.bypasses_blocked)
    lines.append(row(f"  3. Eliminates {_WHITE_BOLD}{bypassed_count}{_RESET} bypass paths"))

    # Bottom border
    lines.append(hline("\u2514", "\u2500", "\u2518"))

    return "\n".join(lines)


def render_combo_warning(combo: ComboFinding, style: int = 4) -> str:
    """Render a combo finding warning in the specified style.

    Args:
        combo: The ComboFinding to render.
        style: 1 = attack chain, 2 = hacker terminal, 3 = security report, 4 = merged.

    Returns:
        ANSI-colored string for terminal output.
    """
    renderers = {
        1: render_combo_warning_v1,
        2: render_combo_warning_v2,
        3: render_combo_warning_v3,
        4: render_combo_warning_v4,
    }
    renderer = renderers.get(style, render_combo_warning_v4)
    return renderer(combo)
