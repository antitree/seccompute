#!/usr/bin/env python3
"""
Plot the distribution of vsDefaultHardeningDeltaPct scores from a seccompute report.

Scores are normalized so that the true floor (-175.3, all dangerous syscalls allowed)
maps to -100, giving a clean -100 to +100 display scale.

Usage:
    python tools/plot_hardening.py /tmp/profile.json
    python tools/plot_hardening.py /tmp/profile.json --out hardening.png
"""

import argparse
import json
import sys

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


# The raw score for a fully permissive profile (all dangerous syscalls allowed).
# Calculated from: (ref_risk - max_risk) / ref_risk * 100
# where max_risk = sum of all HIGH_RISK_WEIGHTS (128.0) and ref_risk = Docker default (46.5)
RAW_FLOOR = -175.3

ANCHORS = [
    (-100, "No filter\n(ALLOW all)"),
    (   0, "Docker\ndefault"),
    ( 100, "Perfect\nlockdown"),
]

ZONES = [
    # (x_start, x_end, color, label)
    (-110, -100, "#4a0000", ""),               # tiny buffer left of floor
    (-100,    0, "#4a0000", "Worse than Default"),
    (   0,   50, "#5b5b5b", "Hardened"),
    (  50,  100, "#003a00", "Well Hardened"),
]


def normalize(raw: np.ndarray) -> np.ndarray:
    """Rescale negative scores so RAW_FLOOR -> -100, leaving positives unchanged."""
    result = raw.copy()
    neg = raw < 0
    result[neg] = raw[neg] * 100.0 / abs(RAW_FLOOR)
    return result


def load_scores(report_path: str) -> list[float]:
    with open(report_path) as f:
        data = json.load(f)
    profiles = data.get("profiles", [])
    return [
        p["vsDefaultHardeningDeltaPct"]
        for p in profiles
        if p.get("valid") and p.get("vsDefaultHardeningDeltaPct") is not None
    ]


def plot(raw_scores: list[float], out_path: str, title: str) -> None:
    raw = np.array(raw_scores)
    scores = normalize(raw)
    n = len(scores)

    x_min, x_max = -110, 110

    fig, (ax_hist, ax_strip) = plt.subplots(
        2, 1,
        figsize=(12, 6),
        gridspec_kw={"height_ratios": [4, 1]},
        facecolor="#1a1a1a",
    )
    fig.subplots_adjust(hspace=0.05)

    for ax in (ax_hist, ax_strip):
        ax.set_facecolor("#1a1a1a")
        ax.set_xlim(x_min, x_max)
        for spine in ax.spines.values():
            spine.set_color("#444")

    # --- Zone backgrounds ---
    for (zx0, zx1, color, _label) in ZONES:
        for ax in (ax_hist, ax_strip):
            ax.axvspan(max(zx0, x_min), min(zx1, x_max), color=color, alpha=0.25, zorder=0)

    # --- Histogram ---
    bins = np.linspace(x_min, x_max, 60)
    counts, edges = np.histogram(scores, bins=bins)

    bar_colors = []
    for left, right in zip(edges[:-1], edges[1:]):
        mid = (left + right) / 2
        if mid < 0:
            bar_colors.append("#ff4444")
        elif mid < 50:
            bar_colors.append("#a0a0a0")
        else:
            bar_colors.append("#44ff44")

    ax_hist.bar(edges[:-1], counts, width=np.diff(edges), color=bar_colors,
                align="edge", alpha=0.85, zorder=2)

    # Stats — compute on normalized scores, show normalized values
    p50 = np.percentile(scores, 50)
    p10 = np.percentile(scores, 10)
    p90 = np.percentile(scores, 90)

    # for val, label, color in [
    #     (p50, f"p50\n{p50:.0f}", "#ffffff"),
    #     (p10, f"p10\n{p10:.0f}", "#ff8c00"),
    #     (p90, f"p90\n{p90:.0f}", "#44ff44"),
    # ]:
    #     ax_hist.axvline(val, color=color, linewidth=1.5, linestyle="--", alpha=0.8, zorder=3)
    #     ax_hist.text(val, counts.max() * 0.95,
    #                  label, color=color, fontsize=8, ha="center", va="top", zorder=4)

    ax_hist.set_ylabel("Number of Profiles", color="#aaa", fontsize=10)
    ax_hist.tick_params(colors="#aaa", labelbottom=False)
    ax_hist.set_title(title, color="#eee", fontsize=13, pad=10)
    ax_hist.text(0.99, 0.97, f"n={n:,} profiles", transform=ax_hist.transAxes,
                 color="#888", fontsize=8, ha="right", va="top")

    # --- Strip / spectrum bar ---
    ax_strip.set_ylim(0, 1)
    ax_strip.set_yticks([])

    jitter = np.random.uniform(0.1, 0.9, size=len(scores))
    dot_colors = ["#ff4444" if s < 0 else "#a0a0a0" if s < 50 else "#44ff44" for s in scores]
    ax_strip.scatter(scores, jitter, c=dot_colors, s=6, alpha=0.4, zorder=2)

    for x_val, label in ANCHORS:
        ax_strip.axvline(x_val, color="#888", linewidth=1, linestyle=":", zorder=3)
        ax_strip.text(x_val, -0.35, label, color="#aaa", fontsize=7,
                      ha="center", va="top", transform=ax_strip.get_xaxis_transform())

    #ax_strip.set_xlabel(
    #    "Hardening Score  (−100 = no filter, 0 = Docker default, +100 = blocks all tracked dangerous syscalls)",
    #    color="#aaa", fontsize=9,
    #)
    ax_strip.set_xlabel(None)
    ax_strip.tick_params(colors="#aaa")

    # --- Legend ---
    legend_patches = [
        mpatches.Patch(color="#ff4444", alpha=0.7, label="Worse than Default (< 0)"),
        mpatches.Patch(color="#88cc44", alpha=0.7, label="Hardened (0 to 50)"),
        mpatches.Patch(color="#44ff44", alpha=0.7, label="Well Hardened (50 to 100)"),
    ]
    ax_hist.legend(handles=legend_patches, loc="upper left", fontsize=8,
                   facecolor="#2a2a2a", edgecolor="#444", labelcolor="#ccc")

    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="#1a1a1a")
    print(f"Saved: {out_path}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot seccompute hardening distribution")
    parser.add_argument("report", help="Path to seccompute report JSON")
    parser.add_argument("--out", default="hardening_distribution.png", help="Output image path")
    parser.add_argument("--title", default="Seccomp Profile Hardening Distribution",
                        help="Chart title")
    args = parser.parse_args()

    scores = load_scores(args.report)
    if not scores:
        print("No valid scores found in report.", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(scores)} profiles.", file=sys.stderr)
    plot(scores, args.out, args.title)


if __name__ == "__main__":
    main()
