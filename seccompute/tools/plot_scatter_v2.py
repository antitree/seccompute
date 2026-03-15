#!/usr/bin/env python3
"""
2D scatter plot of Attack Surface Score (AS) vs Dangerous Exposure Score (DE).

Each dot is one profile. Position encodes both dimensions simultaneously:
  X axis: DE  (-100 = all dangerous syscalls open, 0 = none open)
  Y axis: AS  (0 = no filter, 100 = blocks everything)

Quadrants:
  Top-right:    High AS, low DE  → ideal (tight allowlist, no escape vectors)
  Top-left:     High AS, bad DE  → "danger zone" (looks hardened, has escape vectors)
  Bottom-right: Low AS,  low DE  → lazy but not actively dangerous
  Bottom-left:  Low AS,  bad DE  → worst case

Usage:
    python tools/plot_scatter_v2.py report.json
    python tools/plot_scatter_v2.py report.json --out scatter.png
    python tools/plot_scatter_v2.py report.json --label-outliers
    python tools/plot_scatter_v2.py report.json --slide
    python tools/plot_scatter_v2.py report.json --panel
"""

import argparse
import json
import sys

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyBboxPatch
import numpy as np


BG = "#1a1a1a"
GRID = "#2a2a2a"

# Docker default profile coordinates (pre-computed from DEFAULT-docker.json)
DOCKER_DEFAULT_DE = -7.4
DOCKER_DEFAULT_AS = 7.8

# Quadrant boundary presets
# "runtime" (default): dividers pass through the Docker/runtime default profile
# "center":            symmetric midpoints of each axis scale
BOUNDS_RUNTIME = (DOCKER_DEFAULT_DE, DOCKER_DEFAULT_AS)   # (-7.4, 7.8)
BOUNDS_CENTER  = (-50.0, 50.0)

QUADRANT_COLORS = {
    "ideal":        "#44ff44",   # high AS, clean DE  → best
    "danger_zone":  "#888888",   # high AS, bad DE    → strict but exposed
    "loose_clean":  "#888888",   # low AS, clean DE   → loose but safe
    "loose_danger": "#ff4444",   # low AS, bad DE     → worst
}

QUADRANT_LABELS = {
    "ideal":        "Tight & Clean",
    "danger_zone":  "Tight but Dangerous?",
    "loose_clean":  "What?",
    "loose_danger": "Broad & Dangerous",
}

QUADRANT_DESCRIPTIONS = {
    "ideal":        "Strict allowlist,\nno dangerous\nsyscalls exposed",
    "danger_zone":  "Tight allowlist but\ndangerous syscalls\nstill reachable",
    "loose_clean":  "Broad allowlist\nbut no dangerous\nsyscalls exposed",
    "loose_danger": "Broad allowlist\nAND dangerous\nsyscalls exposed",
}


def load_profiles(report_path: str) -> list[dict]:
    with open(report_path) as f:
        data = json.load(f)
    profiles = [
        p for p in data.get("profiles", [])
        if p.get("valid")
        and p.get("attackSurfaceScore") is not None
        and p.get("dangerousExposureScore") is not None
    ]
    if not profiles:
        print("No profiles with attackSurfaceScore/dangerousExposureScore found.", file=sys.stderr)
        print("Regenerate the report with the current version of seccompute.", file=sys.stderr)
        sys.exit(1)
    return profiles


def classify(de: float, as_: float, de_thresh: float, as_thresh: float) -> str:
    if as_ >= as_thresh and de > de_thresh:
        return "ideal"
    elif as_ >= as_thresh and de <= de_thresh:
        return "danger_zone"
    elif as_ < as_thresh and de > de_thresh:
        return "loose_clean"
    else:
        return "loose_danger"


def pick_outliers(profiles: list[dict], de_thresh: float, as_thresh: float) -> list[dict]:
    """Auto-select interesting profiles to label: worst DE, best AS+DE, danger zone."""
    labeled = []

    # Worst DE (most dangerous exposure)
    by_de = sorted(profiles, key=lambda p: p["dangerousExposureScore"])
    labeled.extend(by_de[:3])

    # Best (high AS, DE=0)
    perfect = [p for p in profiles if p["dangerousExposureScore"] == 0.0]
    if perfect:
        labeled.append(max(perfect, key=lambda p: p["attackSurfaceScore"]))

    # Danger zone: high AS but bad DE (the most interesting cluster)
    danger = [
        p for p in profiles
        if p["attackSurfaceScore"] >= as_thresh
        and p["dangerousExposureScore"] <= de_thresh
    ]
    danger_sorted = sorted(danger, key=lambda p: p["dangerousExposureScore"])
    labeled.extend(danger_sorted[:3])

    # Deduplicate preserving order
    seen = set()
    result = []
    for p in labeled:
        if p["filename"] not in seen:
            seen.add(p["filename"])
            result.append(p)
    return result


def short_name(filename: str, max_len: int = 28) -> str:
    name = filename.replace("seccomp-", "").replace(".json", "")
    if len(name) > max_len:
        name = name[:max_len - 1] + "…"
    return name


def _draw_docker_default(ax, fontsize: int = 18) -> None:
    """Mark the Docker default profile position on any scatter axes."""
    ax.scatter(
        [DOCKER_DEFAULT_DE], [DOCKER_DEFAULT_AS],
        marker="D", s=80, color="#ffffff", zorder=6,
        edgecolors="#aaaaaa", linewidths=0.8,
    )
    ax.annotate(
        "Runtime\ndefault",
        xy=(DOCKER_DEFAULT_DE, DOCKER_DEFAULT_AS),
        xytext=(DOCKER_DEFAULT_DE - 2, DOCKER_DEFAULT_AS -15),
        color="#ffffff", fontsize=fontsize, fontweight="bold",
        ha="right", va="bottom",
        arrowprops=dict(arrowstyle="-", color="#aaa", lw=0.8),
        zorder=7,
    )


def _axis_bounds(de: np.ndarray, as_: np.ndarray):
    de_min = min(de.min() - 5, DOCKER_DEFAULT_DE - 5, -25)
    de_max = 5
    as_min = max(min(as_.min() - 3, DOCKER_DEFAULT_AS - 5), -2)
    as_max = min(as_.max() + 3, 102)
    return de_min, de_max, as_min, as_max


DOT_COLORS_SLIDE = {
    "ideal":        "#70b0af",   # top-right: teal
    "danger_zone":  "#cd5e5d",   # top-left:  gray/white
    "loose_clean":  "#70b0af",   # bottom-right: gray/white
    "loose_danger": "#cd5e5d",   # bottom-left: muted red
}

DOT_COLORS_DEFAULT = {
    "ideal":        "#44ff44",   # green
    "danger_zone":  "#ff4444",   # red
    "loose_clean":  "#44ff44",   # green
    "loose_danger": "#ff4444",   # red
}


def _draw_scatter_core(ax, de, as_, classes, label_outliers, profiles,
                       de_min, de_max, as_min, as_max,
                       de_thresh: float = BOUNDS_RUNTIME[0],
                       as_thresh: float = BOUNDS_RUNTIME[1],
                       dot_size=22, dot_alpha=0.65, slide_mode=False):
    """Shared scatter drawing: shading, dividers, dots, optional outlier labels."""
    counts = {k: classes.count(k) for k in QUADRANT_COLORS}
    n = len(profiles)
    dot_palette = DOT_COLORS_SLIDE if slide_mode else DOT_COLORS_DEFAULT

    # Quadrant shading
    ax.axvspan(-200, de_thresh, ymin=0.5, ymax=1.0,
               color="#333333", alpha=0.30, zorder=0)   # danger_zone: gray
    # ideal (top-right): gradient green at top → transparent at bottom
    _grad_green = np.ones((256, 1, 4))
    _grad_green[:, 0, 0] = 0.0
    _grad_green[:, 0, 1] = np.linspace(0.23, 0.10, 256)
    _grad_green[:, 0, 2] = 0.0
    _grad_green[:, 0, 3] = np.linspace(0.40, 0.0, 256)
    ax.imshow(
        _grad_green,
        aspect="auto",
        extent=[de_thresh, de_max, as_thresh, as_max],
        origin="upper",
        zorder=0,
    )

    # loose_danger (bottom-left): gradient red on left → transparent on right
    _grad = np.ones((1, 256, 4))
    _grad[0, :, 0] = np.linspace(0.29, 0.10, 256)
    _grad[0, :, 1] = 0.0
    _grad[0, :, 2] = 0.0
    _grad[0, :, 3] = np.linspace(0.45, 0.0, 256)
    ax.imshow(
        _grad,
        aspect="auto",
        extent=[de_min, de_thresh, as_min, as_thresh],
        origin="upper",
        zorder=0,
    )

    # Dividers
    ax.axvline(de_thresh, color="#555", linewidth=1.0, linestyle="--", zorder=1)
    ax.axhline(as_thresh, color="#555", linewidth=1.0, linestyle="--", zorder=1)

    # Docker default reference lines (always shown regardless of boundary mode)
    ax.axhline(DOCKER_DEFAULT_AS, color="#ff4444", linewidth=1.0, linestyle=":", alpha=0.7, zorder=1)
    ax.text(
        0.01, DOCKER_DEFAULT_AS,
        "  ← below Docker default",
        color="#ff4444", fontsize=7, alpha=0.8,
        va="bottom", ha="left", transform=ax.get_yaxis_transform(), zorder=2,
    )

    # Dots — colored per quadrant
    for qk in ["loose_clean", "loose_danger", "ideal", "danger_zone"]:
        mask = np.array([c == qk for c in classes])
        if mask.any():
            ax.scatter(
                de[mask], as_[mask],
                c=dot_palette[qk],
                s=dot_size, alpha=dot_alpha, zorder=3,
                edgecolors="none",
            )

    # Outlier labels
    if label_outliers:
        outliers = pick_outliers(profiles, de_thresh, as_thresh)
        for p in outliers:
            x, y = p["dangerousExposureScore"], p["attackSurfaceScore"]
            name = short_name(p["filename"])
            x_off = 3 if x > -50 else -3
            y_off = 1.5
            ax.annotate(
                name,
                xy=(x, y), xytext=(x + x_off, y + y_off),
                color="#ccc", fontsize=6.5,
                arrowprops=dict(arrowstyle="-", color="#555", lw=0.8),
                zorder=5,
            )

    ax.set_xlim(de_min, de_max)
    ax.set_ylim(as_min, as_max)
    ax.set_facecolor(BG)
    for spine in ax.spines.values():
        spine.set_color("#444")

    return counts


def _xticks(ax, de_min, de_max, de_thresh: float = BOUNDS_RUNTIME[0],
            center_mode: bool = False, fontsize=7):
    step = 10 if (de_max - de_min) <= 50 else 20
    thresh_int = int(de_thresh)
    ticks = sorted(set(
        [0, thresh_int] +
        list(range(0, int(de_min) - 1, -step))
    ))
    tick_labels = []
    for t in ticks:
        if t == 0:
            tick_labels.append("0\n(clean)")
        elif t == thresh_int:
            label = "(center)" if center_mode else "(runtime default)"
            tick_labels.append(f"{t}\n{label}")
        else:
            tick_labels.append(str(t))
    ax.set_xticks(ticks)
    ax.set_xticklabels(tick_labels, color="#aaa", fontsize=fontsize)


# ─────────────────────────────────────────────────────────────────────────────
# Mode: default (scatter + marginal histograms)
# ─────────────────────────────────────────────────────────────────────────────

def plot(profiles: list[dict], out_path: str, title: str, label_outliers: bool,
         bounds: tuple[float, float] = BOUNDS_RUNTIME) -> None:
    de_thresh, as_thresh = bounds
    de = np.array([p["dangerousExposureScore"] for p in profiles])
    as_ = np.array([p["attackSurfaceScore"] for p in profiles])
    classes = [classify(d, a, de_thresh, as_thresh) for d, a in zip(de, as_)]
    n = len(profiles)
    de_min, de_max, as_min, as_max = _axis_bounds(de, as_)

    fig = plt.figure(figsize=(16, 9), facecolor=BG)

    gs = fig.add_gridspec(
        2, 2,
        width_ratios=[4, 1],
        height_ratios=[1, 4],
        hspace=0.05, wspace=0.05,
        left=0.09, right=0.97, top=0.92, bottom=0.10,
    )
    ax = fig.add_subplot(gs[1, 0])
    ax_top = fig.add_subplot(gs[0, 0])
    ax_right = fig.add_subplot(gs[1, 1])

    counts = _draw_scatter_core(ax, de, as_, classes, label_outliers, profiles,
                                de_min, de_max, as_min, as_max,
                                de_thresh=de_thresh, as_thresh=as_thresh)
    _draw_docker_default(ax, fontsize=17)

    # Quadrant text labels
    quad_text = [
        (0.25, 0.75, "danger_zone"),
        (0.25, 0.25, "loose_danger"),
        (0.75, 0.75, "ideal"),
        (0.75, 0.25, "loose_clean"),
    ]
    for tx, ty, qk in quad_text:
        c = counts[qk]
        if c > 0:
            ax.text(
                tx, ty,
                f"{QUADRANT_LABELS[qk]}\n{c} profiles ({100*c//n}%)",
                color="#666", fontsize=8, ha="center", va="center",
                style="italic", zorder=2, transform=ax.transAxes,
            )

    ax.set_xlabel(
        "Dangerous Exposure Score  (0 = no dangerous syscalls open, −100 = all open)",
        color="#aaa", fontsize=9,
    )
    ax.set_ylabel(
        "Attack Surface Score  (100 = blocks everything, 0 = no filter)",
        color="#aaa", fontsize=9,
    )
    ax.tick_params(colors="#aaa", labelsize=8)
    _xticks(ax, de_min, de_max, de_thresh=de_thresh,
            center_mode=(bounds == BOUNDS_CENTER))

    # Marginal: DE (top)
    ax_top.hist(de, bins=40, range=(de_min, de_max), color="#888", alpha=0.6)
    ax_top.set_xlim(de_min, de_max)
    ax_top.set_xticks([])
    ax_top.set_yticks([])
    ax_top.set_facecolor(BG)
    ax_top.tick_params(colors="#aaa")
    ax_top.set_title(title, color="#eee", fontsize=12, pad=8)
    for spine in ax_top.spines.values():
        spine.set_color("#444")

    # Marginal: AS (right)
    ax_right.hist(as_, bins=40, range=(as_min, as_max), orientation="horizontal",
                  color="#888", alpha=0.6)
    ax_right.set_ylim(as_min, as_max)
    ax_right.set_xticks([])
    ax_right.set_yticks([])
    ax_right.set_facecolor(BG)
    for spine in ax_right.spines.values():
        spine.set_color("#444")

    # Legend
    patches = [
        mpatches.Patch(color=QUADRANT_COLORS[k], alpha=0.8,
                       label=f"{QUADRANT_LABELS[k]}  (n={counts[k]})")
        for k in ["ideal", "danger_zone", "loose_clean", "loose_danger"]
        if counts[k] > 0
    ]
    ax.legend(
        handles=patches, loc="upper left", fontsize=8,
        facecolor="#2a2a2a", edgecolor="#444", labelcolor="#ccc",
    )

    ax.text(0.99, 0.01, f"n={n:,} profiles", transform=ax.transAxes,
            color="#666", fontsize=8, ha="right", va="bottom")

    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=BG)
    print(f"Saved: {out_path}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# Mode: --slide  (clean single-panel, presentation-ready)
# ─────────────────────────────────────────────────────────────────────────────

def plot_slide(profiles: list[dict], out_path: str, title: str, label_outliers: bool,
               bounds: tuple[float, float] = BOUNDS_RUNTIME) -> None:
    de_thresh, as_thresh = bounds
    de = np.array([p["dangerousExposureScore"] for p in profiles])
    as_ = np.array([p["attackSurfaceScore"] for p in profiles])
    classes = [classify(d, a, de_thresh, as_thresh) for d, a in zip(de, as_)]
    n = len(profiles)
    de_min, de_max, as_min, as_max = _axis_bounds(de, as_)

    fig, ax = plt.subplots(figsize=(16, 9), facecolor=BG)
    # More left margin for Y-axis labels, tighter top (no subtitle row)
    fig.subplots_adjust(left=0.08, right=0.97, top=0.92, bottom=0.13)

    counts = _draw_scatter_core(ax, de, as_, classes, label_outliers, profiles,
                                de_min, de_max, as_min, as_max,
                                de_thresh=de_thresh, as_thresh=as_thresh,
                                dot_size=50, dot_alpha=0.80, slide_mode=True)
    _draw_docker_default(ax, fontsize=21)

    # Bold quadrant labels directly on chart
    quad_text = [
        (0.22, 0.80, "danger_zone"),
        (0.22, 0.20, "loose_danger"),
        (0.88, 0.80, "ideal"),
        (0.88, 0.20, "loose_clean"),
    ]
    for tx, ty, qk in quad_text:
        c = counts[qk]
        pct = 100 * c // n if n else 0
        color = QUADRANT_COLORS[qk]
        ax.text(
            tx, ty,
            QUADRANT_LABELS[qk],
            color=color, fontsize=26, fontweight="bold",
            ha="center", va="center", zorder=2,
            transform=ax.transAxes, alpha=0.90,
        )
        if c > 0:
            ax.text(
                tx, ty - 0.08,
                f"{c} profiles  ({pct}%)",
                color="#bbb", fontsize=11,
                ha="center", va="center", zorder=2,
                transform=ax.transAxes,
            )

    # X axis: plain-English label
    ax.set_xlabel(
        "← More dangerous syscalls exposed                                                           Clean →",
        color="#aaa", fontsize=21, labelpad=21,
    )
    # Y axis: drop the title word, just show the directional hint at top/bottom
    ax.set_ylabel("")
    ax.yaxis.set_tick_params(labelsize=11, labelcolor="#aaa")
    # Add rotated end-labels manually as axis annotations
    ax.text(-0.04, 0.02, "← Broad allowlist", color="#aaa", fontsize=21,
            ha="center", va="bottom", rotation=90, transform=ax.transAxes)
    ax.text(-0.04, 0.98, "Strict allowlist →", color="#aaa", fontsize=21,
            ha="center", va="top", rotation=90, transform=ax.transAxes)

    ax.tick_params(colors="#aaa", labelsize=11)
    _xticks(ax, de_min, de_max, de_thresh=de_thresh,
            center_mode=(bounds == BOUNDS_CENTER), fontsize=10)

    # Title only — no subtitle
    fig.text(0.5, 0.96, title, color="#eee", fontsize=18, fontweight="bold",
             ha="center", va="top")

    # Legend — upper left, dot colors match slide palette
    patches = [
        mpatches.Patch(color=DOT_COLORS_SLIDE[k], alpha=0.90,
                       label=QUADRANT_LABELS[k])
        for k in ["ideal", "danger_zone", "loose_clean", "loose_danger"]
        if counts[k] > 0
    ]
    ax.legend(
        handles=patches, loc="upper left", fontsize=11,
        facecolor="#222", edgecolor="#555", labelcolor="#ddd",
        framealpha=0.9,
    )

    ax.text(0.99, 0.01, f"n={n:,} profiles", transform=ax.transAxes,
            color="#555", fontsize=9, ha="right", va="bottom")

    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=BG)
    print(f"Saved: {out_path}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# Mode: --panel  (two square panels: scatter left, breakdown table right)
# ─────────────────────────────────────────────────────────────────────────────

def plot_panel(profiles: list[dict], out_path: str, title: str, label_outliers: bool,
               bounds: tuple[float, float] = BOUNDS_RUNTIME) -> None:
    de_thresh, as_thresh = bounds
    de = np.array([p["dangerousExposureScore"] for p in profiles])
    as_ = np.array([p["attackSurfaceScore"] for p in profiles])
    classes = [classify(d, a, de_thresh, as_thresh) for d, a in zip(de, as_)]
    n = len(profiles)
    de_min, de_max, as_min, as_max = _axis_bounds(de, as_)

    fig = plt.figure(figsize=(16, 9), facecolor=BG)
    gs = gridspec.GridSpec(
        1, 2,
        width_ratios=[1, 1],
        left=0.06, right=0.97,
        top=0.88, bottom=0.12,
        wspace=0.10,
    )

    # ── Left panel: scatter ────────────────────────────────────────────────
    ax_scatter = fig.add_subplot(gs[0])
    counts = _draw_scatter_core(ax_scatter, de, as_, classes, label_outliers, profiles,
                                de_min, de_max, as_min, as_max,
                                de_thresh=de_thresh, as_thresh=as_thresh,
                                dot_size=36, dot_alpha=0.75)
    _draw_docker_default(ax_scatter, fontsize=8)

    # Quadrant labels on scatter
    quad_text = [
        (0.22, 0.82, "danger_zone"),
        (0.22, 0.18, "loose_danger"),
        (0.78, 0.82, "ideal"),
        (0.78, 0.18, "loose_clean"),
    ]
    for tx, ty, qk in quad_text:
        c = counts[qk]
        color = QUADRANT_COLORS[qk]
        ax_scatter.text(
            tx, ty, QUADRANT_LABELS[qk],
            color=color, fontsize=11, fontweight="bold",
            ha="center", va="center", zorder=2,
            transform=ax_scatter.transAxes, alpha=0.85,
        )
        if c > 0:
            pct = 100 * c // n
            ax_scatter.text(
                tx, ty - 0.08, f"{c}  ({pct}%)",
                color="#aaa", fontsize=9,
                ha="center", va="center", zorder=2,
                transform=ax_scatter.transAxes,
            )

    ax_scatter.set_xlabel(
        "← More dangerous exposure            Clean (0) →",
        color="#aaa", fontsize=21, labelpad=8,
    )
    ax_scatter.set_ylabel(
        "Attack Surface Score\n(higher = stricter allowlist)",
        color="#aaa", fontsize=21, labelpad=8,
    )
    ax_scatter.tick_params(colors="#aaa", labelsize=8)
    _xticks(ax_scatter, de_min, de_max, de_thresh=de_thresh,
            center_mode=(bounds == BOUNDS_CENTER), fontsize=7)
    ax_scatter.yaxis.set_tick_params(labelsize=8, labelcolor="#aaa")
    ax_scatter.set_title("Profile Distribution", color="#eee", fontsize=12, pad=10)

    ax_scatter.text(0.99, 0.01, f"n={n:,}", transform=ax_scatter.transAxes,
                    color="#555", fontsize=8, ha="right", va="bottom")

    # ── Right panel: 2×2 breakdown tiles ──────────────────────────────────
    ax_table = fig.add_subplot(gs[1])
    ax_table.set_facecolor(BG)
    ax_table.set_xlim(0, 2)
    ax_table.set_ylim(0, 2)
    ax_table.axis("off")
    ax_table.set_title("Quadrant Breakdown", color="#eee", fontsize=12, pad=10)

    # tile layout: (col, row) in ax_table coords — row 1 = top
    tile_layout = [
        (0, 1, "danger_zone"),   # top-left
        (1, 1, "ideal"),         # top-right
        (0, 0, "loose_danger"),  # bottom-left
        (1, 0, "loose_clean"),   # bottom-right
    ]

    pad = 0.06
    for col, row, qk in tile_layout:
        c = counts[qk]
        pct = 100 * c // n if n else 0
        color = QUADRANT_COLORS[qk]
        x0 = col + pad
        y0 = row + pad
        w = 1 - 2 * pad
        h = 1 - 2 * pad

        # Tile background
        rect = FancyBboxPatch(
            (x0, y0), w, h,
            boxstyle="round,pad=0.03",
            facecolor=color, alpha=0.12,
            edgecolor=color, linewidth=1.5,
            zorder=1,
        )
        ax_table.add_patch(rect)

        # Quadrant name
        ax_table.text(
            x0 + w / 2, y0 + h * 0.72,
            QUADRANT_LABELS[qk],
            color=color, fontsize=11, fontweight="bold",
            ha="center", va="center", zorder=2,
        )

        # Description
        ax_table.text(
            x0 + w / 2, y0 + h * 0.45,
            QUADRANT_DESCRIPTIONS[qk],
            color="#aaa", fontsize=8,
            ha="center", va="center", zorder=2,
            linespacing=1.4,
        )

        # Count / percentage — large
        ax_table.text(
            x0 + w / 2, y0 + h * 0.16,
            f"{c} profiles  ·  {pct}%",
            color="#eee", fontsize=10, fontweight="bold",
            ha="center", va="center", zorder=2,
        )

    # Axis labels as corner annotations on the tile grid
    ax_table.text(0.5, 2.02, "← High Attack Surface →", color="#666", fontsize=8,
                  ha="center", va="bottom")
    ax_table.text(-0.04, 1.0, "← Clean\nExposure\n→ Dangerous", color="#666", fontsize=7,
                  ha="right", va="center", rotation=90)

    # ── Shared title ───────────────────────────────────────────────────────
    fig.text(0.5, 0.93, title, color="#eee", fontsize=14, fontweight="bold", ha="center")
    fig.text(0.5, 0.90,
             "Each dot = one seccomp profile  ·  Top-right quadrant is safest",
             color="#777", fontsize=8, ha="center")

    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=BG)
    print(f"Saved: {out_path}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="2D scatter: Attack Surface vs Dangerous Exposure")
    parser.add_argument("report", help="Path to seccompute report JSON")
    parser.add_argument("--out", default="scatter_v2.png", help="Output image path")
    parser.add_argument("--title", default="Seccomp Profile Security Scatter",
                        help="Chart title")
    parser.add_argument("--label-outliers", action="store_true",
                        help="Annotate interesting outlier profiles")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--slide", action="store_true",
                      help="Slide-deck mode: clean single panel, larger dots, plain-English labels")
    mode.add_argument("--panel", action="store_true",
                      help="Panel mode: scatter (left) + 2×2 quadrant breakdown tiles (right)")

    parser.add_argument(
        "--center-bounds", action="store_true",
        help="Use symmetric center boundaries (DE=-50, AS=50) instead of runtime-default boundaries",
    )

    args = parser.parse_args()
    bounds = BOUNDS_CENTER if args.center_bounds else BOUNDS_RUNTIME

    profiles = load_profiles(args.report)
    print(f"Loaded {len(profiles)} profiles.", file=sys.stderr)

    if args.slide:
        plot_slide(profiles, args.out, args.title, args.label_outliers, bounds=bounds)
    elif args.panel:
        plot_panel(profiles, args.out, args.title, args.label_outliers, bounds=bounds)
    else:
        plot(profiles, args.out, args.title, args.label_outliers, bounds=bounds)


if __name__ == "__main__":
    main()
