#!/usr/bin/env python3
"""
Grid heatmap: Attack Surface Score vs Dangerous Syscall Coverage.

Bins both axes into an NxN grid and colors cells by profile count.
Dark background theme.

Modes:
    default          standard figure (10x9)
    --slide          presentation size (16x9) with larger fonts
    --annotate       show bin range text inside each cell
    --bins N         number of bins per axis (default: 10)
    --hex            hexagonal binning instead of square grid

Usage:
    python tools/plot_heatmap.py report.json
    python tools/plot_heatmap.py report.json --out heatmap.png --title "My Title"
    python tools/plot_heatmap.py report.json --slide
    python tools/plot_heatmap.py report.json --annotate
    python tools/plot_heatmap.py report.json --bins 20
    python tools/plot_heatmap.py report.json --hex
    python tools/plot_heatmap.py report.json --hex --slide
"""

import argparse
import json
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
import numpy as np


# ── constants ────────────────────────────────────────────────────────────────

BG = "#1a1a1a"

# Docker default position
DOCKER_DEFAULT_AS = 7.8
DOCKER_DEFAULT_DE = -7.4
DOCKER_DEFAULT_PCT_BLOCKED = 100 + DOCKER_DEFAULT_DE  # 92.6


# ── custom colormap ──────────────────────────────────────────────────────────

def _make_cmap():
    """Dark background -> dark teal -> bright yellow/white."""
    return LinearSegmentedColormap.from_list(
        "heatmap_dark",
        [
            (0.00, "#1a1a1a"),   # zero / empty — same as background
            (0.05, "#0d2e3a"),   # barely occupied — very dark teal
            (0.15, "#0f4055"),   # low
            (0.30, "#147070"),   # moderate low
            (0.50, "#1a9a80"),   # moderate
            (0.70, "#50c878"),   # moderate high — emerald
            (0.85, "#ffe066"),   # high — yellow
            (1.00, "#fffbe6"),   # peak — near-white yellow
        ],
    )


# ── data loading ─────────────────────────────────────────────────────────────

def load_profiles(report_path: str) -> list:
    with open(report_path) as f:
        data = json.load(f)
    profiles = [
        p for p in data.get("profiles", [])
        if p.get("valid")
        and p.get("attackSurfaceScore") is not None
        and p.get("dangerousExposureScore") is not None
    ]
    if not profiles:
        print("No valid profiles with required scores found.", file=sys.stderr)
        sys.exit(1)
    return profiles


def _extract_axes(profiles):
    """Return (attack_surface, pct_dangerous_blocked) arrays."""
    as_scores = np.array([p["attackSurfaceScore"] for p in profiles])
    de_scores = np.array([p["dangerousExposureScore"] for p in profiles])
    # Convert DE to pct_dangerous_blocked: DE ranges -100..0, pct = 100 + DE
    pct_blocked = 100.0 + de_scores
    return as_scores, pct_blocked


def _bin_index(value, edges):
    """Return bin index (0..N_BINS-1) for a value given bin edges."""
    for i in range(len(edges) - 1):
        if value < edges[i + 1]:
            return i
    return len(edges) - 2  # clamp to last bin


def _build_grid(as_scores, pct_blocked, edges):
    """Return NxN count grid. grid[row][col] where row=pct_blocked bin, col=AS bin."""
    n_bins = len(edges) - 1
    grid = np.zeros((n_bins, n_bins), dtype=int)
    for a, p in zip(as_scores, pct_blocked):
        col = _bin_index(a, edges)
        row = _bin_index(p, edges)
        grid[row, col] += 1
    return grid


# ── plotting ─────────────────────────────────────────────────────────────────

def plot_heatmap(profiles, out_path, title, slide_mode=False, annotate=False, n_bins=10):
    step = 100 // n_bins
    edges = list(range(0, 101, step))
    # Ensure last edge is exactly 100
    if edges[-1] != 100:
        edges[-1] = 100
    cell_size = step  # width/height of each cell in data units

    as_scores, pct_blocked = _extract_axes(profiles)
    grid = _build_grid(as_scores, pct_blocked, edges)
    n = len(profiles)
    vmax = grid.max()

    # Font sizes — scale down for finer grids so labels fit
    base_count = max(4, 16 - (n_bins - 5))   # shrink count font as bins increase
    base_annot = max(4, 9 - (n_bins - 5))

    if slide_mode:
        fs_title = 24
        fs_axis = 18
        fs_tick = 12
        fs_count = max(6, base_count + 6)
        fs_annot = max(4, base_annot + 2)
        fs_docker = 12
        fs_ncount = 14
        figsize = (16, 9)
    else:
        fs_title = 16
        fs_axis = 13
        fs_tick = 9
        fs_count = base_count
        fs_annot = base_annot
        fs_docker = 9
        fs_ncount = 10
        figsize = (10, 9)

    cmap = _make_cmap()

    fig, ax = plt.subplots(figsize=figsize, facecolor=BG)
    ax.set_facecolor(BG)

    grid_float = grid.astype(float)

    im = ax.imshow(
        grid_float,
        extent=[0, 100, 0, 100],
        origin="lower",
        aspect="auto",
        cmap=cmap,
        vmin=0,
        vmax=vmax,
        interpolation="nearest",
        zorder=1,
    )

    # Draw cell borders
    for edge in edges:
        ax.axhline(edge, color="#444444", linewidth=0.5, zorder=2)
        ax.axvline(edge, color="#444444", linewidth=0.5, zorder=2)

    # Text inside cells: count numbers and optional annotations
    half = cell_size / 2.0
    for row in range(n_bins):
        for col in range(n_bins):
            count = grid[row, col]
            cx = edges[col] + half
            cy = edges[row] + half

            if count > 0:
                ax.text(
                    cx, cy, str(count),
                    ha="center", va="center",
                    color="#ffffff", fontsize=fs_count, fontweight="bold",
                    zorder=4,
                )

            if annotate:
                label = (
                    f"AS {edges[col]}-{edges[col+1]}\n"
                    f"DB {edges[row]}-{edges[row+1]}"
                )
                offset = -half * 0.4 if count > 0 else 0
                ax.text(
                    cx, cy + offset, label,
                    ha="center", va="top",
                    color="#888888", fontsize=fs_annot,
                    zorder=4,
                )

    # Docker default marker — placed at exact coordinates, not cell center
    ax.scatter(
        [DOCKER_DEFAULT_AS], [DOCKER_DEFAULT_PCT_BLOCKED],
        marker="D", s=120 if slide_mode else 80,
        color="#ffffff", zorder=6,
        edgecolors="#aaaaaa", linewidths=1.0,
    )
    ax.annotate(
        "Runtime\ndefault",
        xy=(DOCKER_DEFAULT_AS, DOCKER_DEFAULT_PCT_BLOCKED),
        xytext=(DOCKER_DEFAULT_AS + cell_size * 1.2, DOCKER_DEFAULT_PCT_BLOCKED - cell_size * 0.6),
        color="#ffffff", fontsize=fs_docker, fontweight="bold",
        ha="left", va="top",
        arrowprops=dict(arrowstyle="-", color="#aaa", lw=0.8),
        zorder=7,
    )

    # Axes labels and ticks
    ax.set_xlabel(
        "Syscall Coverage  (% of all syscalls restricted)",
        color="#cccccc", fontsize=fs_axis, labelpad=10,
    )
    ax.set_ylabel(
        "Dangerous Syscall Coverage  (% of dangerous syscalls blocked)",
        color="#cccccc", fontsize=fs_axis, labelpad=10,
    )

    # Show tick labels only every other edge for dense grids
    tick_step = 2 if n_bins > 10 else 1
    shown_edges = edges[::tick_step]
    ax.set_xticks(shown_edges)
    ax.set_yticks(shown_edges)
    ax.set_xticklabels([str(e) for e in shown_edges], color="#aaaaaa", fontsize=fs_tick)
    ax.set_yticklabels([str(e) for e in shown_edges], color="#aaaaaa", fontsize=fs_tick)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)

    for spine in ax.spines.values():
        spine.set_color("#444444")
    ax.tick_params(colors="#aaaaaa")

    # Title
    ax.set_title(title, color="#eeeeee", fontsize=fs_title, pad=14)

    # Profile count
    ax.text(
        0.99, 0.01, f"n={n:,} profiles",
        transform=ax.transAxes, color="#777777", fontsize=fs_ncount,
        ha="right", va="bottom", zorder=5,
    )

    # Colorbar
    cbar = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cbar.set_label("Profile count", color="#aaaaaa", fontsize=fs_tick)
    cbar.ax.tick_params(colors="#aaaaaa", labelsize=fs_tick - 1)
    cbar.outline.set_edgecolor("#444444")

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    print(f"Saved: {out_path}", file=sys.stderr)


# ── hexagonal binning ────────────────────────────────────────────────────────

def plot_hexbin(profiles, out_path, title, slide_mode=False, n_bins=10):
    """Hexagonal binning chart using matplotlib's built-in hexbin."""
    as_scores, pct_blocked = _extract_axes(profiles)
    n = len(profiles)

    if slide_mode:
        fs_title = 24
        fs_axis = 18
        fs_tick = 12
        fs_docker = 12
        fs_ncount = 14
        figsize = (16, 9)
    else:
        fs_title = 16
        fs_axis = 13
        fs_tick = 9
        fs_docker = 9
        fs_ncount = 10
        figsize = (10, 9)

    cmap = _make_cmap()

    fig, ax = plt.subplots(figsize=figsize, facecolor=BG)
    ax.set_facecolor(BG)

    hb = ax.hexbin(
        as_scores, pct_blocked,
        gridsize=n_bins,
        cmap=cmap,
        mincnt=1,          # only color cells that have at least 1 profile
        extent=[0, 100, 0, 100],
        linewidths=0.4,
        edgecolors="#333333",
        zorder=2,
    )

    # Docker default marker
    ax.scatter(
        [DOCKER_DEFAULT_AS], [DOCKER_DEFAULT_PCT_BLOCKED],
        marker="D", s=120 if slide_mode else 80,
        color="#ffffff", zorder=6,
        edgecolors="#aaaaaa", linewidths=1.0,
    )
    ax.annotate(
        "Runtime\ndefault",
        xy=(DOCKER_DEFAULT_AS, DOCKER_DEFAULT_PCT_BLOCKED),
        xytext=(DOCKER_DEFAULT_AS + 8, DOCKER_DEFAULT_PCT_BLOCKED - 6),
        color="#ffffff", fontsize=fs_docker, fontweight="bold",
        ha="left", va="top",
        arrowprops=dict(arrowstyle="-", color="#aaa", lw=0.8),
        zorder=7,
    )

    ax.set_xlabel(
        "Syscall Coverage  (% of all syscalls restricted)",
        color="#cccccc", fontsize=fs_axis, labelpad=10,
    )
    ax.set_ylabel(
        "Dangerous Syscall Coverage  (% of dangerous syscalls blocked)",
        color="#cccccc", fontsize=fs_axis, labelpad=10,
    )

    tick_vals = list(range(0, 101, 100 // n_bins))
    ax.set_xticks(tick_vals)
    ax.set_yticks(tick_vals)
    ax.set_xticklabels([str(v) for v in tick_vals], color="#aaaaaa", fontsize=fs_tick)
    ax.set_yticklabels([str(v) for v in tick_vals], color="#aaaaaa", fontsize=fs_tick)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)

    for spine in ax.spines.values():
        spine.set_color("#444444")
    ax.tick_params(colors="#aaaaaa")

    ax.set_title(title, color="#eeeeee", fontsize=fs_title, pad=14)
    ax.text(
        0.99, 0.01, f"n={n:,} profiles",
        transform=ax.transAxes, color="#777777", fontsize=fs_ncount,
        ha="right", va="bottom", zorder=5,
    )

    cbar = fig.colorbar(hb, ax=ax, fraction=0.03, pad=0.02)
    cbar.set_label("Profile count", color="#aaaaaa", fontsize=fs_tick)
    cbar.ax.tick_params(colors="#aaaaaa", labelsize=fs_tick - 1)
    cbar.outline.set_edgecolor("#444444")

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    print(f"Saved: {out_path}", file=sys.stderr)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Grid heatmap of seccomp profile security scores"
    )
    parser.add_argument("report", help="Path to seccompute report JSON")
    parser.add_argument("--out", default="heatmap.png", help="Output image path")
    parser.add_argument(
        "--title",
        default="Seccomp Profile Security Heatmap",
        help="Chart title",
    )
    parser.add_argument(
        "--slide", action="store_true",
        help="Presentation mode (16x9, larger fonts)",
    )
    parser.add_argument(
        "--annotate", action="store_true",
        help="Show bin range labels inside each cell",
    )
    parser.add_argument(
        "--bins", type=int, default=10,
        help="Number of bins per axis (default: 10 → 10x10 grid, step=10; use 20 for step=5)",
    )
    parser.add_argument(
        "--hex", action="store_true",
        help="Hexagonal binning instead of square grid",
    )

    args = parser.parse_args()

    profiles = load_profiles(args.report)
    print(f"Loaded {len(profiles)} profiles.", file=sys.stderr)

    if args.hex:
        plot_hexbin(
            profiles, args.out, args.title,
            slide_mode=args.slide, n_bins=args.bins,
        )
    else:
        if 100 % args.bins != 0:
            print(f"Error: --bins must evenly divide 100 (e.g. 5, 10, 20, 25, 50). Got {args.bins}.", file=sys.stderr)
            sys.exit(1)
        plot_heatmap(
            profiles, args.out, args.title,
            slide_mode=args.slide, annotate=args.annotate, n_bins=args.bins,
        )


if __name__ == "__main__":
    main()
