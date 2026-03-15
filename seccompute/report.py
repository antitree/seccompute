"""Output formatting: JSON, NDJSON, CSV."""

from __future__ import annotations

import csv
import gzip
import io
import statistics
import sys
from pathlib import Path
from typing import Any

try:
    import orjson

    def _dumps(obj: Any) -> str:
        return orjson.dumps(obj, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS).decode()

    def _dumps_line(obj: Any) -> str:
        return orjson.dumps(obj).decode()
except ImportError:
    import json

    def _dumps(obj: Any) -> str:
        return json.dumps(obj, indent=2, sort_keys=True)

    def _dumps_line(obj: Any) -> str:
        return json.dumps(obj, sort_keys=True)


def _open_out(path: Path, use_gzip: bool):
    if use_gzip:
        return gzip.open(str(path) + ".gz", "wt", encoding="utf-8")
    return open(path, "w", encoding="utf-8")


def build_report(
    profiles: list[dict],
    summary: dict,
    reference_runtime: str,
    reference_profile: str,
) -> dict:
    """Assemble the full JSON report from accumulated per-profile data."""
    from .weights import DANGEROUS_SYSCALLS, WEIGHTS_PACK

    valid_profiles = [p for p in profiles if p["valid"]]

    # hardeningOverview
    deltas = [p["vsDefaultHardeningDeltaPct"] for p in valid_profiles]
    top_improved = sorted(
        [{"filename": p["filename"], "deltaPct": p["vsDefaultHardeningDeltaPct"]} for p in valid_profiles],
        key=lambda x: x["deltaPct"],
        reverse=True,
    )[:10]
    top_regressed = sorted(
        [{"filename": p["filename"], "deltaPct": p["vsDefaultHardeningDeltaPct"]} for p in valid_profiles],
        key=lambda x: x["deltaPct"],
    )[:10]

    hardening_overview: dict[str, Any] = {
        "avgDeltaPct": round(statistics.mean(deltas), 1) if deltas else 0.0,
        "p50DeltaPct": round(statistics.median(deltas), 1) if deltas else 0.0,
        "p90DeltaPct": round(_percentile(deltas, 90), 1) if deltas else 0.0,
        "topImprovedProfiles": top_improved,
        "topRegressedProfiles": top_regressed,
    }

    # vsNoneOverview
    coverages = [p["vsNoneCoveragePct"] for p in valid_profiles]
    blocked_counts = [p["dangerousBlockedCount"] for p in valid_profiles]
    allowed_counts = [
        len(p["dangerousAllowedUnconditionally"]) + len(p["dangerousAllowedConditionally"])
        for p in valid_profiles
    ]
    vs_none_overview = {
        "avgCoveragePct": round(statistics.mean(coverages), 1) if coverages else 0.0,
        "avgDangerousBlocked": round(statistics.mean(blocked_counts), 1) if blocked_counts else 0.0,
        "avgDangerousAllowed": round(statistics.mean(allowed_counts), 1) if allowed_counts else 0.0,
    }

    # dangerousReachability: aggregate across valid profiles
    reach: dict[str, dict[str, int]] = {
        sc: {"reachableUnconditionally": 0, "reachableConditionally": 0, "blocked": 0}
        for sc in sorted(DANGEROUS_SYSCALLS)
    }
    for p in valid_profiles:
        for sc in p["dangerousAllowedUnconditionally"]:
            if sc in reach:
                reach[sc]["reachableUnconditionally"] += 1
        for sc in p["dangerousAllowedConditionally"]:
            if sc in reach:
                reach[sc]["reachableConditionally"] += 1
        # blocked = total_valid - unconditional - conditional
    for sc in sorted(DANGEROUS_SYSCALLS):
        reach[sc]["blocked"] = (
            len(valid_profiles)
            - reach[sc]["reachableUnconditionally"]
            - reach[sc]["reachableConditionally"]
        )

    # conditionUsage: sum across all valid profiles
    condition_usage: dict[str, int] = {
        "capInclude": 0,
        "capExclude": 0,
        "argFilter": 0,
        "archInclude": 0,
        "minKernel": 0,
    }
    for p in valid_profiles:
        for k, v in p.get("_conditionUsage", {}).items():
            condition_usage[k] = condition_usage.get(k, 0) + v

    # Strip internal fields from profile output
    clean_profiles = []
    for p in profiles:
        cp = {k: v for k, v in p.items() if not k.startswith("_")}
        clean_profiles.append(cp)

    return {
        "summary": {
            "totalScanned": summary["totalScanned"],
            "skippedInvalid": summary["skippedInvalid"],
            "skippedDefaultCopies": summary["skippedDefaultCopies"],
            "analyzed": summary["analyzed"],
            "referenceRuntime": reference_runtime,
            "referenceProfile": reference_profile,
            "weightsPack": WEIGHTS_PACK,
        },
        "hardeningOverview": hardening_overview,
        "vsNoneOverview": vs_none_overview,
        "dangerousReachability": reach,
        "conditionUsage": condition_usage,
        "profiles": clean_profiles,
    }


def _percentile(data: list[float], pct: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    n = len(sorted_data)
    if n == 1:
        return sorted_data[0]
    k = (n - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, n - 1)
    frac = k - lo
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * frac


def write_json(report: dict, out_path: Path | None, use_gzip: bool) -> None:
    text = _dumps(report)
    if out_path is None:
        sys.stdout.write(text)
        sys.stdout.write("\n")
    else:
        with _open_out(out_path, use_gzip) as f:
            f.write(text)
            f.write("\n")


def write_json_split(report: dict, base: Path, use_gzip: bool) -> None:
    sections = {
        "summary": {"summary": report["summary"]},
        "aggregates": {
            "hardeningOverview": report["hardeningOverview"],
            "vsNoneOverview": report["vsNoneOverview"],
            "dangerousReachability": report["dangerousReachability"],
            "conditionUsage": report["conditionUsage"],
        },
        "profiles": {"profiles": report["profiles"]},
    }
    for name, data in sections.items():
        write_json(data, base.parent / f"{base.stem}_{name}.json", use_gzip)


def write_ndjson(profiles: list[dict], report: dict, out_path: Path | None, use_gzip: bool) -> None:
    lines: list[str] = []
    for p in profiles:
        cp = {k: v for k, v in p.items() if not k.startswith("_")}
        lines.append(_dumps_line(cp))
    # Final summary line
    tail = {
        "type": "summary",
        "summary": report["summary"],
        "hardeningOverview": report["hardeningOverview"],
        "vsNoneOverview": report["vsNoneOverview"],
    }
    lines.append(_dumps_line(tail))

    text = "\n".join(lines) + "\n"
    if out_path is None:
        sys.stdout.write(text)
    else:
        with _open_out(out_path, use_gzip) as f:
            f.write(text)


def write_csv(profiles: list[dict], out_path: Path | None, use_gzip: bool) -> None:
    fieldnames = [
        "filename", "sha256", "valid",
        "vsDefaultHardeningDeltaPct", "defaultRisk", "profileRisk",
        "vsNoneCoveragePct", "dangerousBlockedCount",
    ]

    def _write(f: Any) -> None:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for p in profiles:
            writer.writerow({k: p.get(k, "") for k in fieldnames})

    if out_path is None:
        buf = io.StringIO()
        _write(buf)
        sys.stdout.write(buf.getvalue())
    else:
        with _open_out(out_path, use_gzip) as f:
            _write(f)
