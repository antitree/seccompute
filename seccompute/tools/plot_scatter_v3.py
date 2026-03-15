#!/usr/bin/env python3
"""
Improved 2D scatter: Attack Surface Score (AS) vs Dangerous Exposure Score (DE).

Fixes three readability problems in v2 without biasing results:
  1. Axis clipping   — axes zoom to data range (+ padding), not fixed 0-100/-100-0
  2. Decoupled bounds — quadrant dividers sit at the runtime default position
                        independently of axis limits; no more wasted whitespace
  3. KDE density mode (--density) — replaces individual dots with a 2D kernel
                        density heatmap so cluster shape is immediately legible

Modes:
    default          scatter with clipped axes + decoupled quadrant boundaries
    --slide          same, presentation fonts, larger dots
    --density        KDE heatmap + sparse dot overlay + marginal histograms
    --density --slide density mode with presentation fonts

Boundary options (same as v2, passed through):
    default          runtime default coordinates (DE=-7.4, AS=7.8)
    --center-bounds  symmetric midpoints (DE=-50, AS=50)

Usage:
    python tools/plot_scatter_v3.py report.json
    python tools/plot_scatter_v3.py report.json --slide
    python tools/plot_scatter_v3.py report.json --density
    python tools/plot_scatter_v3.py report.json --density --slide
    python tools/plot_scatter_v3.py report.json --center-bounds
"""

import argparse
import json
import sys

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyBboxPatch
import numpy as np
from scipy.stats import gaussian_kde


# ── shared constants (keep in sync with v2) ───────────────────────────────────

BG    = "#1a1a1a"
GRID  = "#2a2a2a"

DOCKER_DEFAULT_DE = -7.4
DOCKER_DEFAULT_AS = 7.8

BOUNDS_RUNTIME = (DOCKER_DEFAULT_DE, DOCKER_DEFAULT_AS)
BOUNDS_CENTER  = (-50.0, 50.0)

QUADRANT_COLORS = {
    "ideal":        "#44ff44",
    "danger_zone":  "#888888",
    "loose_clean":  "#888888",
    "loose_danger": "#ff4444",
}

QUADRANT_LABELS = {
    "ideal":        "Tight & Clean",
    "danger_zone":  "Tight but Dangerous?",
    "loose_clean":  "",
    "loose_danger": "Broad & Dangerous",
}

DOT_COLORS_SLIDE = {
    "ideal":        "#70b0af",
    "danger_zone":  "#cd5e5d",
    "loose_clean":  "#70b0af",
    "loose_danger": "#cd5e5d",
}

DOT_COLORS_DEFAULT = {
    "ideal":        "#44ff44",
    "danger_zone":  "#ff4444",
    "loose_clean":  "#44ff44",
    "loose_danger": "#ff4444",
}


# ── data loading ──────────────────────────────────────────────────────────────

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


# ── axis bounds: clipped to data, quadrant thresholds stay independent ────────

def _axis_bounds_clipped(de: np.ndarray, as_: np.ndarray,
                         de_thresh: float, as_thresh: float,
                         de_pad: float = 3.0, as_pad: float = 3.0):
    """
    Clip axes to the actual data range plus padding.
    Ensures both the quadrant dividers and the Docker default marker
    are always visible inside the frame.
    """
    de_min = min(de.min(), DOCKER_DEFAULT_DE, de_thresh) - de_pad
    de_max = max(de.max(), DOCKER_DEFAULT_DE, de_thresh) + de_pad
    as_min = max(min(as_.min(), DOCKER_DEFAULT_AS, as_thresh) - as_pad, -2.0)
    as_max = min(max(as_.max(), DOCKER_DEFAULT_AS, as_thresh) + as_pad, 102.0)
    return de_min, de_max, as_min, as_max


# ── shared drawing helpers ────────────────────────────────────────────────────

def _style_ax(ax):
    ax.set_facecolor(BG)
    for spine in ax.spines.values():
        spine.set_color("#444")


def _draw_docker_default(ax, fontsize: int = 11) -> None:
    ax.scatter(
        [DOCKER_DEFAULT_DE], [DOCKER_DEFAULT_AS],
        marker="D", s=70, color="#ffffff", zorder=8,
        edgecolors="#aaaaaa", linewidths=0.8,
    )
    ax.annotate(
        "Runtime\ndefault",
        xy=(DOCKER_DEFAULT_DE, DOCKER_DEFAULT_AS),
        xytext=(DOCKER_DEFAULT_DE - 2, DOCKER_DEFAULT_AS - 10),
        color="#ffffff", fontsize=fontsize, fontweight="bold",
        ha="right", va="bottom",
        arrowprops=dict(arrowstyle="-", color="#aaa", lw=0.8),
        zorder=9,
    )


def _draw_quadrant_shading(ax, de_min, de_max, as_min, as_max,
                           de_thresh, as_thresh):
    """Gradient fills for the two 'bad' quadrants; flat tint for good ones."""
    # danger_zone (top-left): flat gray
    ax.axvspan(de_min - 10, de_thresh, ymin=0.0, ymax=1.0,
               color="#333333", alpha=0.0, zorder=0)   # reset — handled per-half below

    # Compute ymin/ymax fractions for the horizontal split at as_thresh
    as_range = as_max - as_min
    y_frac = (as_thresh - as_min) / as_range if as_range else 0.5
    y_frac = max(0.0, min(1.0, y_frac))

    # Top-left: danger_zone — flat gray tint
    ax.axvspan(de_min - 10, de_thresh, ymin=y_frac, ymax=1.0,
               color="#333333", alpha=0.20, zorder=0)

    # Top-right: ideal — green gradient top → transparent bottom
    _gg = np.ones((256, 1, 4))
    _gg[:, 0, 0] = 0.0
    _gg[:, 0, 1] = np.linspace(0.23, 0.10, 256)
    _gg[:, 0, 2] = 0.0
    _gg[:, 0, 3] = np.linspace(0.40, 0.0, 256)
    ax.imshow(_gg, aspect="auto",
              extent=[de_thresh, de_max + 10, as_thresh, as_max + 10],
              origin="upper", zorder=0)

    # Bottom-left: loose_danger — red gradient left → transparent right
    _rg = np.ones((1, 256, 4))
    _rg[0, :, 0] = np.linspace(0.29, 0.10, 256)
    _rg[0, :, 1] = 0.0
    _rg[0, :, 2] = 0.0
    _rg[0, :, 3] = np.linspace(0.45, 0.0, 256)
    ax.imshow(_rg, aspect="auto",
              extent=[de_min - 10, de_thresh, as_min - 10, as_thresh],
              origin="upper", zorder=0)


def _draw_dividers_and_guides(ax, de_thresh, as_thresh, fontsize=7):
    # Quadrant dividers
    ax.axvline(de_thresh, color="#555", linewidth=1.0, linestyle="--", zorder=1)
    ax.axhline(as_thresh, color="#555", linewidth=1.0, linestyle="--", zorder=1)
    # Docker default AS guide
    ax.axhline(DOCKER_DEFAULT_AS, color="#ff4444", linewidth=0.9,
               linestyle=":", alpha=0.65, zorder=1)
    ax.text(0.01, DOCKER_DEFAULT_AS, "  ← below Docker default",
            color="#ff4444", fontsize=fontsize, alpha=0.75,
            va="bottom", ha="left", transform=ax.get_yaxis_transform(), zorder=2)


def _draw_dots(ax, de, as_, classes, slide_mode, dot_size, dot_alpha):
    palette = DOT_COLORS_SLIDE if slide_mode else DOT_COLORS_DEFAULT
    for qk in ["loose_clean", "loose_danger", "ideal", "danger_zone"]:
        mask = np.array([c == qk for c in classes])
        if mask.any():
            ax.scatter(de[mask], as_[mask],
                       c=palette[qk], s=dot_size, alpha=dot_alpha,
                       zorder=4, edgecolors="none")


def _xticks(ax, de_min, de_max, de_thresh, center_mode=False, fontsize=7):
    span = de_max - de_min
    step = 5 if span <= 30 else 10 if span <= 60 else 20
    thresh_int = int(round(de_thresh))
    raw = list(range(0, int(de_min) - 1, -step))
    ticks = sorted(set([0, thresh_int] + raw))
    labels = []
    for t in ticks:
        if t == 0:
            labels.append("0\n(clean)")
        elif t == thresh_int:
            labels.append(f"{t}\n({'center' if center_mode else 'runtime default'})")
        else:
            labels.append(str(t))
    ax.set_xticks(ticks)
    ax.set_xticklabels(labels, color="#aaa", fontsize=fontsize)


def _quadrant_count_labels(ax, counts, n, slide_mode, fontsize_label, fontsize_count):
    """Overlay quadrant name + count at fixed axes-fraction positions."""
    positions = [
        (0.18, 0.82, "danger_zone"),
        (0.18, 0.18, "loose_danger"),
        (0.82, 0.82, "ideal"),
        (0.82, 0.18, "loose_clean"),
    ]
    for tx, ty, qk in positions:
        c = counts[qk]
        pct = 100 * c // n if n else 0
        color = QUADRANT_COLORS[qk]
        label = QUADRANT_LABELS[qk]
        if label:
            ax.text(tx, ty, label,
                    color=color, fontsize=fontsize_label, fontweight="bold",
                    ha="center", va="center", zorder=5,
                    transform=ax.transAxes, alpha=0.90)
        if c > 0:
            ax.text(tx, ty - 0.09, f"{c}  ({pct}%)",
                    color="#bbb", fontsize=fontsize_count,
                    ha="center", va="center", zorder=5,
                    transform=ax.transAxes)


# ── KDE helpers ───────────────────────────────────────────────────────────────

def _kde_heatmap(ax, de, as_, de_min, de_max, as_min, as_max, resolution=200):
    """
    Draw a 2D Gaussian KDE heatmap.  Color scale: dark background → bright
    yellow-white at peak density.  Returns the highest-density point.
    """
    # Build grid
    xi = np.linspace(de_min, de_max, resolution)
    yi = np.linspace(as_min, as_max, resolution)
    xx, yy = np.meshgrid(xi, yi)
    positions = np.vstack([xx.ravel(), yy.ravel()])

    # Fit KDE (Scott's bandwidth by default — sensible for n~100-10k)
    kde = gaussian_kde(np.vstack([de, as_]))
    zz = kde(positions).reshape(resolution, resolution)

    # Normalize to [0, 1] for colormapping
    zz /= zz.max()

    # Custom colormap: transparent at zero density → opaque at peak
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list(
        "density",
        [(0.0, "#1a1a1a"),   # background — effectively transparent
         (0.15, "#1a3a4a"),  # very sparse: dark teal
         (0.40, "#1a6a7a"),  # moderate
         (0.65, "#20a890"),  # medium-high: teal-green
         (0.85, "#ffe066"),  # high: yellow
         (1.0,  "#ffffff")], # peak: white
    )

    im = ax.imshow(
        zz,
        extent=[de_min, de_max, as_min, as_max],
        origin="lower",
        aspect="auto",
        cmap=cmap,
        alpha=0.85,
        zorder=2,
        interpolation="bilinear",
    )
    return im, kde


# ── Mode: default scatter (v3 improvements) ──────────────────────────────────

def plot(profiles, out_path, title, bounds, slide_mode=False):
    de_thresh, as_thresh = bounds
    center_mode = (bounds == BOUNDS_CENTER)

    de  = np.array([p["dangerousExposureScore"] for p in profiles])
    as_ = np.array([p["attackSurfaceScore"]     for p in profiles])
    classes = [classify(d, a, de_thresh, as_thresh) for d, a in zip(de, as_)]
    counts  = {k: classes.count(k) for k in QUADRANT_COLORS}
    n = len(profiles)

    de_min, de_max, as_min, as_max = _axis_bounds_clipped(
        de, as_, de_thresh, as_thresh)

    dot_size  = 50  if slide_mode else 22
    dot_alpha = 0.80 if slide_mode else 0.65
    fs_label  = 22  if slide_mode else 10
    fs_count  = 11  if slide_mode else 8
    fs_axis   = 14  if slide_mode else 9
    fs_tick   = 10  if slide_mode else 7
    fs_docker = 18  if slide_mode else 9

    fig = plt.figure(figsize=(16, 9), facecolor=BG)
    gs = fig.add_gridspec(
        2, 2,
        width_ratios=[4, 1], height_ratios=[1, 4],
        hspace=0.05, wspace=0.05,
        left=0.09, right=0.97, top=0.92, bottom=0.10,
    )
    ax       = fig.add_subplot(gs[1, 0])
    ax_top   = fig.add_subplot(gs[0, 0])
    ax_right = fig.add_subplot(gs[1, 1])

    _draw_quadrant_shading(ax, de_min, de_max, as_min, as_max, de_thresh, as_thresh)
    _draw_dividers_and_guides(ax, de_thresh, as_thresh, fontsize=fs_docker - 2)
    _draw_dots(ax, de, as_, classes, slide_mode, dot_size, dot_alpha)
    _draw_docker_default(ax, fontsize=fs_docker)

    _quadrant_count_labels(ax, counts, n, slide_mode, fs_label, fs_count)

    ax.set_xlim(de_min, de_max)
    ax.set_ylim(as_min, as_max)
    _style_ax(ax)

    ax.set_xlabel(
        "← More dangerous syscalls exposed          Clean (0) →",
        color="#aaa", fontsize=fs_axis,
    )
    ax.set_ylabel(
        "Attack Surface Score  (100 = blocks everything)",
        color="#aaa", fontsize=fs_axis,
    )
    ax.tick_params(colors="#aaa", labelsize=fs_tick)
    _xticks(ax, de_min, de_max, de_thresh, center_mode, fontsize=fs_tick)
    ax.yaxis.set_tick_params(labelcolor="#aaa", labelsize=fs_tick)

    # Marginal: DE (top)
    ax_top.hist(de, bins=40, range=(de_min, de_max), color="#888", alpha=0.6)
    ax_top.set_xlim(de_min, de_max)
    ax_top.set_xticks([]); ax_top.set_yticks([])
    ax_top.set_facecolor(BG)
    ax_top.set_title(title, color="#eee", fontsize=12, pad=8)
    for spine in ax_top.spines.values(): spine.set_color("#444")

    # Marginal: AS (right)
    ax_right.hist(as_, bins=40, range=(as_min, as_max),
                  orientation="horizontal", color="#888", alpha=0.6)
    ax_right.set_ylim(as_min, as_max)
    ax_right.set_xticks([]); ax_right.set_yticks([])
    ax_right.set_facecolor(BG)
    for spine in ax_right.spines.values(): spine.set_color("#444")

    # Legend
    palette = DOT_COLORS_SLIDE if slide_mode else DOT_COLORS_DEFAULT
    patches = [
        mpatches.Patch(color=palette[k], alpha=0.85,
                       label=f"{QUADRANT_LABELS[k]}  (n={counts[k]})")
        for k in ["ideal", "danger_zone", "loose_clean", "loose_danger"]
        if counts[k] > 0 and QUADRANT_LABELS[k]
    ]
    ax.legend(handles=patches, loc="upper left", fontsize=max(fs_count - 1, 7),
              facecolor="#2a2a2a", edgecolor="#444", labelcolor="#ccc")

    ax.text(0.99, 0.01, f"n={n:,} profiles",
            transform=ax.transAxes, color="#666", fontsize=7,
            ha="right", va="bottom")

    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=BG)
    print(f"Saved: {out_path}", file=sys.stderr)


# ── Mode: --density  (KDE heatmap + sparse dots + marginals) ─────────────────

def plot_density(profiles, out_path, title, bounds, slide_mode=False):
    """
    KDE density heatmap showing where profiles cluster, with individual dots
    rendered at low opacity on top.  Marginal histograms on two sides.

    Fixes options 1, 2, and 4 simultaneously:
      - Axes clipped to data (option 1)
      - Quadrant dividers independent of axis range (option 2)
      - Density replaces uniform dot field (option 4)
    """
    de_thresh, as_thresh = bounds
    center_mode = (bounds == BOUNDS_CENTER)

    de  = np.array([p["dangerousExposureScore"] for p in profiles])
    as_ = np.array([p["attackSurfaceScore"]     for p in profiles])
    classes = [classify(d, a, de_thresh, as_thresh) for d, a in zip(de, as_)]
    counts  = {k: classes.count(k) for k in QUADRANT_COLORS}
    n = len(profiles)

    de_min, de_max, as_min, as_max = _axis_bounds_clipped(
        de, as_, de_thresh, as_thresh, de_pad=4.0, as_pad=4.0)

    fs_label  = 20 if slide_mode else 10
    fs_count  = 11 if slide_mode else 8
    fs_axis   = 13 if slide_mode else 9
    fs_tick   = 10 if slide_mode else 7
    fs_docker = 16 if slide_mode else 9

    fig = plt.figure(figsize=(16, 9), facecolor=BG)
    gs = fig.add_gridspec(
        2, 2,
        width_ratios=[4, 1], height_ratios=[1, 4],
        hspace=0.05, wspace=0.05,
        left=0.09, right=0.97, top=0.92, bottom=0.10,
    )
    ax       = fig.add_subplot(gs[1, 0])
    ax_top   = fig.add_subplot(gs[0, 0])
    ax_right = fig.add_subplot(gs[1, 1])

    # ── KDE heatmap (drawn first, below everything) ────────────────────────
    _kde_heatmap(ax, de, as_, de_min, de_max, as_min, as_max, resolution=250)

    # ── Quadrant shading (drawn on top of KDE at low alpha) ───────────────
    _draw_quadrant_shading(ax, de_min, de_max, as_min, as_max, de_thresh, as_thresh)

    # ── Sparse dots: small, low-alpha, so KDE shape dominates ─────────────
    _draw_dots(ax, de, as_, classes,
               slide_mode=False,   # use default palette for dots over KDE
               dot_size=12, dot_alpha=0.35)

    # ── Overlays ──────────────────────────────────────────────────────────
    _draw_dividers_and_guides(ax, de_thresh, as_thresh, fontsize=fs_docker - 2)
    _draw_docker_default(ax, fontsize=fs_docker)
    _quadrant_count_labels(ax, counts, n, slide_mode, fs_label, fs_count)

    ax.set_xlim(de_min, de_max)
    ax.set_ylim(as_min, as_max)
    _style_ax(ax)

    ax.set_xlabel(
        "← More dangerous syscalls exposed          Clean (0) →",
        color="#aaa", fontsize=fs_axis,
    )
    ax.set_ylabel(
        "Attack Surface Score  (100 = blocks everything)",
        color="#aaa", fontsize=fs_axis,
    )
    ax.tick_params(colors="#aaa", labelsize=fs_tick)
    _xticks(ax, de_min, de_max, de_thresh, center_mode, fontsize=fs_tick)
    ax.yaxis.set_tick_params(labelcolor="#aaa", labelsize=fs_tick)

    # ── Marginal histograms ───────────────────────────────────────────────
    # Top: DE distribution — color bars by which side of de_thresh they fall
    bins_de = np.linspace(de_min, de_max, 50)
    counts_de, edges_de = np.histogram(de, bins=bins_de)
    bar_c_de = ["#ff4444" if (e + edges_de[i+1])/2 <= de_thresh else "#44ff44"
                for i, e in enumerate(edges_de[:-1])]
    ax_top.bar(edges_de[:-1], counts_de, width=np.diff(edges_de),
               color=bar_c_de, alpha=0.65, align="edge")
    ax_top.set_xlim(de_min, de_max)
    ax_top.set_xticks([]); ax_top.set_yticks([])
    ax_top.set_facecolor(BG)
    ax_top.set_title(title, color="#eee", fontsize=12, pad=8)
    for spine in ax_top.spines.values(): spine.set_color("#444")

    # Right: AS distribution — color bars by as_thresh
    bins_as = np.linspace(as_min, as_max, 50)
    counts_as, edges_as = np.histogram(as_, bins=bins_as)
    bar_c_as = ["#44ff44" if (e + edges_as[i+1])/2 >= as_thresh else "#888888"
                for i, e in enumerate(edges_as[:-1])]
    ax_right.barh(edges_as[:-1], counts_as, height=np.diff(edges_as),
                  color=bar_c_as, alpha=0.65, align="edge")
    ax_right.set_ylim(as_min, as_max)
    ax_right.set_xticks([]); ax_right.set_yticks([])
    ax_right.set_facecolor(BG)
    for spine in ax_right.spines.values(): spine.set_color("#444")

    # ── Colorbar legend for density ───────────────────────────────────────
    from matplotlib.colors import LinearSegmentedColormap
    cmap_legend = LinearSegmentedColormap.from_list(
        "density",
        ["#1a1a1a", "#1a3a4a", "#1a6a7a", "#20a890", "#ffe066", "#ffffff"])
    sm = plt.cm.ScalarMappable(cmap=cmap_legend,
                               norm=plt.Normalize(vmin=0, vmax=1))
    sm.set_array([])
    cbar = fig.colorbar(sm, ax=ax_right, fraction=0.5, pad=0.08,
                        orientation="vertical")
    cbar.set_label("Relative\ndensity", color="#aaa", fontsize=7)
    cbar.ax.tick_params(colors="#aaa", labelsize=6)
    cbar.outline.set_edgecolor("#444")

    ax.text(0.99, 0.01, f"n={n:,} profiles",
            transform=ax.transAxes, color="#666", fontsize=7,
            ha="right", va="bottom")

    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=BG)
    print(f"Saved: {out_path}", file=sys.stderr)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Improved 2D scatter: clipped axes, decoupled bounds, KDE density mode"
    )
    parser.add_argument("report", help="Path to seccompute report JSON")
    parser.add_argument("--out", default="scatter_v3.png", help="Output image path")
    parser.add_argument("--title", default="Seccomp Profile Security Scatter")

    parser.add_argument("--slide", action="store_true",
                        help="Presentation mode: larger dots/fonts, less clutter")
    parser.add_argument("--density", action="store_true",
                        help="KDE density heatmap mode (option 4)")
    parser.add_argument("--center-bounds", action="store_true",
                        help="Symmetric center boundaries (DE=-50, AS=50)")

    args = parser.parse_args()
    bounds = BOUNDS_CENTER if args.center_bounds else BOUNDS_RUNTIME

    profiles = load_profiles(args.report)
    print(f"Loaded {len(profiles)} profiles.", file=sys.stderr)

    if args.density:
        plot_density(profiles, args.out, args.title, bounds, slide_mode=args.slide)
    else:
        plot(profiles, args.out, args.title, bounds, slide_mode=args.slide)


if __name__ == "__main__":
    main()
