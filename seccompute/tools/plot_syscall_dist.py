#!/usr/bin/env python3
"""
Dangerous syscall exposure distribution chart.

For each dangerous syscall, shows what fraction of profiles block it,
ordered left-to-right by tier (T1 most dangerous → T3 least).
Within each tier syscalls are sorted by block rate descending (most blocked first).

Bar color:
    green    >= 80% of profiles block it
    yellow   50–80%
    orange   20–50%
    red      < 20% (widely exposed)

A horizontal reference line marks the Docker default block rate per syscall.

Usage:
    python tools/plot_syscall_dist.py report.json
    python tools/plot_syscall_dist.py report.json --out dist.png --title "My Title"
    python tools/plot_syscall_dist.py report.json --slide
"""

import argparse
import json
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# Import tier lists directly from weights_v2
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent.parent))
from seccompute.weights_v2 import TIER1, TIER2, TIER3

# ── constants ────────────────────────────────────────────────────────────────

BG = "#1a1a1a"
GRID_COLOR = "#2a2a2a"

# Tier colors (for section labels / dividers)
T1_COLOR = "#c0392b"   # deep red
T2_COLOR = "#e67e22"   # orange
T3_COLOR = "#f1c40f"   # yellow

# Bar fill thresholds
def _bar_color(block_pct):
    if block_pct >= 80:
        return "#2ecc71"   # green — well blocked
    elif block_pct >= 50:
        return "#f1c40f"   # yellow — moderate
    elif block_pct >= 20:
        return "#e67e22"   # orange — exposed
    else:
        return "#e74c3c"   # red — widely open


# ── data loading ─────────────────────────────────────────────────────────────

def load_profiles(report_path):
    with open(report_path) as f:
        data = json.load(f)
    profiles = [p for p in data.get("profiles", []) if p.get("valid")]
    if not profiles:
        print("No valid profiles found.", file=sys.stderr)
        sys.exit(1)
    return profiles


def _syscall_block_rates(profiles):
    """
    For each dangerous syscall return (block_pct, conditional_pct, allowed_pct).
    Uses dangerousAllowedUnconditionally / dangerousAllowedConditionally lists;
    anything not in either list is considered blocked.
    """
    all_dangerous = TIER1 + TIER2 + TIER3
    n = len(profiles)

    allowed_counts = {sc: 0 for sc in all_dangerous}
    conditional_counts = {sc: 0 for sc in all_dangerous}

    for p in profiles:
        for sc in p.get("dangerousAllowedUnconditionally", []):
            if sc in allowed_counts:
                allowed_counts[sc] += 1
        for sc in p.get("dangerousAllowedConditionally", []):
            if sc in conditional_counts:
                conditional_counts[sc] += 1

    rates = {}
    for sc in all_dangerous:
        a = allowed_counts[sc]
        c = conditional_counts[sc]
        b = n - a - c
        rates[sc] = {
            "block_pct": b * 100.0 / n,
            "conditional_pct": c * 100.0 / n,
            "allowed_pct": a * 100.0 / n,
        }
    return rates, n


def _ordered_syscalls(rates):
    """Return syscalls in tier order, sorted by block_pct descending within each tier."""
    def tier_sorted(tier):
        return sorted(tier, key=lambda sc: rates[sc]["block_pct"], reverse=True)

    t1 = tier_sorted(TIER1)
    t2 = tier_sorted(TIER2)
    t3 = tier_sorted(TIER3)
    return t1, t2, t3


# ── plotting ─────────────────────────────────────────────────────────────────

def plot_dist(profiles, out_path, title, slide_mode=False):
    rates, n = _syscall_block_rates(profiles)
    t1, t2, t3 = _ordered_syscalls(rates)
    ordered = t1 + t2 + t3

    # x positions with small gap between tiers
    GAP = 0.8   # extra space between tier groups (in bar-width units)
    BAR_W = 0.7

    positions = []
    x = 0.0
    tier_spans = {}  # tier_name -> (x_start, x_end, label, color)
    for tier_name, tier_syscalls, color in [("T1", t1, T1_COLOR), ("T2", t2, T2_COLOR), ("T3", t3, T3_COLOR)]:
        x_start = x
        for sc in tier_syscalls:
            positions.append(x)
            x += 1.0
        x_end = x - 1.0
        tier_spans[tier_name] = (x_start, x_end, tier_syscalls, color)
        x += GAP  # gap before next tier

    block_pcts   = [rates[sc]["block_pct"]      for sc in ordered]
    cond_pcts    = [rates[sc]["conditional_pct"] for sc in ordered]
    allowed_pcts = [rates[sc]["allowed_pct"]     for sc in ordered]

    if slide_mode:
        fs_title  = 22
        fs_axis   = 15
        fs_tick   = 10
        fs_label  = 8
        fs_tier   = 13
        fs_legend = 10
        figsize   = (22, 9)
        rotation  = 55
    else:
        fs_title  = 16
        fs_axis   = 12
        fs_tick   = 8
        fs_label  = 7
        fs_tier   = 11
        fs_legend = 9
        figsize   = (18, 8)
        rotation  = 55

    fig, ax = plt.subplots(figsize=figsize, facecolor=BG)
    ax.set_facecolor(BG)

    # Single bar per syscall: height = % of profiles that ALLOW it (tall = bad)
    # Blocked profiles simply contribute nothing — no bar.
    exposed_pcts = [allowed_pcts[i] + cond_pcts[i] for i in range(len(ordered))]
    bar_fill = [
        "#e67e22" if cond_pcts[i] > allowed_pcts[i] else "#e74c3c"
        for i in range(len(ordered))
    ]

    ax.bar(
        positions, allowed_pcts,
        width=BAR_W, color="#e74c3c", alpha=0.9, label="Allowed unconditionally", zorder=2,
    )
    ax.bar(
        positions, cond_pcts,
        width=BAR_W, bottom=allowed_pcts, color="#e67e22", alpha=0.85,
        label="Conditional / partial", zorder=2,
    )

    # 100% line
    ax.axhline(100, color="#555555", linewidth=0.6, linestyle="--", zorder=1)

    # Tier section backgrounds and labels
    for tier_name, (x_start, x_end, tier_syscalls, color) in tier_spans.items():
        span_left  = x_start - BAR_W / 2 - 0.1
        span_right = x_end   + BAR_W / 2 + 0.1
        ax.axvspan(span_left, span_right, color=color, alpha=0.06, zorder=0)
        ax.axvline(span_left,  color=color, linewidth=1.0, alpha=0.4, zorder=1)
        ax.axvline(span_right, color=color, linewidth=1.0, alpha=0.4, zorder=1)
        mid = (x_start + x_end) / 2
        tier_labels = {"T1": "Tier 1 — Critical", "T2": "Tier 2 — Serious", "T3": "Tier 3 — Elevated"}
        ax.text(
            mid, 103, tier_labels[tier_name],
            ha="center", va="bottom", color=color,
            fontsize=fs_tier, fontweight="bold", zorder=4,
        )

    # x-axis tick labels = syscall names
    ax.set_xticks(positions)
    ax.set_xticklabels(ordered, rotation=rotation, ha="right", color="#cccccc", fontsize=fs_tick)

    ax.set_ylabel("% of profiles that allow this syscall", color="#cccccc", fontsize=fs_axis, labelpad=8)
    ax.set_ylim(0, 112)
    ax.set_xlim(positions[0] - BAR_W, positions[-1] + BAR_W)

    ax.yaxis.grid(True, color=GRID_COLOR, linewidth=0.6, zorder=0)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_color("#444444")
    ax.tick_params(colors="#aaaaaa", axis="y")
    ax.tick_params(axis="x", length=0)

    ax.set_title(title, color="#eeeeee", fontsize=fs_title, pad=20)
    ax.text(
        0.99, 0.98, f"n={n:,} profiles",
        transform=ax.transAxes, color="#777777", fontsize=fs_legend,
        ha="right", va="top",
    )

    # Legend
    legend_patches = [
        mpatches.Patch(color="#e74c3c", alpha=0.9, label="Allowed unconditionally"),
        mpatches.Patch(color="#e67e22", alpha=0.85, label="Conditional / partial"),
    ]
    ax.legend(
        handles=legend_patches, loc="upper right",
        fontsize=fs_legend, facecolor="#2a2a2a",
        edgecolor="#444", labelcolor="#cccccc",
    )

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    print(f"Saved: {out_path}", file=sys.stderr)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Dangerous syscall exposure distribution across profiles"
    )
    parser.add_argument("report", help="Path to seccompute report JSON")
    parser.add_argument("--out", default="syscall_dist.png", help="Output image path")
    parser.add_argument(
        "--title",
        default="Dangerous Syscall Exposure Distribution",
        help="Chart title",
    )
    parser.add_argument(
        "--slide", action="store_true",
        help="Presentation mode (22x9, larger fonts)",
    )

    args = parser.parse_args()
    profiles = load_profiles(args.report)
    print(f"Loaded {len(profiles)} profiles.", file=sys.stderr)
    plot_dist(profiles, args.out, args.title, slide_mode=args.slide)


if __name__ == "__main__":
    main()
