#!/usr/bin/env python3
"""analyze_profiles v2 — batch-analyzes OCI seccomp profiles.

Usage:
    python seccompute/analyze.py <profilesDir> [options]

Exit codes:
    0 — success
    2 — invalid CLI usage or nonexistent profilesDir
    4 — failed to load reference default profile
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Allow running as a script from repo root
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    __package__ = "seccompute"

from .model import (
    _condition_usage,
    _syscall_states,
    is_valid,
    reference_states_and_risk,
    score_profile,
    sha256_file,
)
from .default_profiles import resolve_default_profile
from .report import build_report, write_csv, write_json, write_json_split, write_ndjson
from .weights import DANGEROUS_SYSCALLS


def _log(event: dict, verbose: bool) -> None:
    if verbose:
        print(json.dumps(event, sort_keys=True), file=sys.stderr)


def _load_json(path: Path) -> tuple[dict | None, str | None]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except json.JSONDecodeError:
        return None, "json_error"
    except OSError as e:
        return None, f"os_error:{e.strerror}"


def _all_syscall_names(profile: dict) -> set[str]:
    names: set[str] = set()
    for rule in profile.get("syscalls", []):
        names.update(rule.get("names", []))
    return names


def _is_default_copy(profile: dict, ref_names: set[str], tolerance: int = 5) -> bool:
    names = _all_syscall_names(profile)
    if not names:
        return True
    return len(names.symmetric_difference(ref_names)) <= tolerance


def _process_file(
    filepath: Path,
    ref_states: dict[str, str],
    ref_risk: float,
    ref_names: set[str],
    verbose: bool,
) -> dict:
    size = filepath.stat().st_size
    _log({"event": "parsing", "file": filepath.name, "size": size}, verbose)

    data, err_reason = _load_json(filepath)
    if data is None:
        _log({"event": "invalid", "file": filepath.name, "reason": err_reason}, verbose)
        return {
            "filename": filepath.name,
            "sha256": "",
            "valid": False,
            "skippedReason": err_reason,
            "vsDefaultHardeningDeltaPct": 0.0,
            "defaultRisk": 0.0,
            "profileRisk": 0.0,
            "vsNoneCoveragePct": 0.0,
            "dangerousBlockedCount": 0,
            "dangerousAllowedUnconditionally": [],
            "dangerousAllowedConditionally": [],
            "improvedSyscalls": [],
            "regressedSyscalls": [],
            "_skipped": "invalid",
        }

    valid, reason = is_valid(data)
    if not valid:
        _log({"event": "invalid", "file": filepath.name, "reason": reason}, verbose)
        return {
            "filename": filepath.name,
            "sha256": sha256_file(str(filepath)),
            "valid": False,
            "skippedReason": reason,
            "vsDefaultHardeningDeltaPct": 0.0,
            "defaultRisk": 0.0,
            "profileRisk": 0.0,
            "vsNoneCoveragePct": 0.0,
            "dangerousBlockedCount": 0,
            "dangerousAllowedUnconditionally": [],
            "dangerousAllowedConditionally": [],
            "improvedSyscalls": [],
            "regressedSyscalls": [],
            "_skipped": "invalid",
        }

    if _is_default_copy(data, ref_names):
        _log({"event": "skipped", "file": filepath.name, "reason": "default_copy"}, verbose)
        return {
            "filename": filepath.name,
            "sha256": sha256_file(str(filepath)),
            "valid": True,
            "skippedReason": "default_copy",
            "vsDefaultHardeningDeltaPct": 0.0,
            "defaultRisk": 0.0,
            "profileRisk": 0.0,
            "vsNoneCoveragePct": 0.0,
            "dangerousBlockedCount": 0,
            "dangerousAllowedUnconditionally": [],
            "dangerousAllowedConditionally": [],
            "improvedSyscalls": [],
            "regressedSyscalls": [],
            "_skipped": "default_copy",
        }

    metrics = score_profile(data, ref_states, ref_risk)
    cond_usage = _condition_usage(data)

    _log({"event": "analyzed", "file": filepath.name, "deltaPct": metrics["vsDefaultHardeningDeltaPct"]}, verbose)

    return {
        "filename": filepath.name,
        "sha256": sha256_file(str(filepath)),
        "valid": True,
        "skippedReason": None,
        **metrics,
        "_conditionUsage": cond_usage,
        "_skipped": None,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="analyze_profiles",
        description="Batch-analyze OCI seccomp profiles and emit hardening metrics.",
    )
    parser.add_argument("profiles_dir", help="Directory containing *.json seccomp profiles, or a single .json profile file")
    parser.add_argument(
        "--reference", choices=["docker", "podman", "containerd"], default="docker",
        help="Reference default profile (default: docker)",
    )
    parser.add_argument(
        "--reference-path", dest="reference_path", default=None,
        help="Path to a specific reference profile JSON file (overrides auto-resolution)",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Use only locally cached profiles; do not fetch from remote sources",
    )
    parser.add_argument(
        "--format", dest="formats", action="append", choices=["json", "ndjson", "csv"],
        default=None, metavar="FORMAT",
        help="Output format(s): json, ndjson, csv (default: json; repeatable)",
    )
    parser.add_argument(
        "--out", dest="out", default=None,
        help="Base output path (default: stdout for JSON)",
    )
    parser.add_argument(
        "--split", action="store_true",
        help="Write separate files per section (summary, aggregates, profiles)",
    )
    parser.add_argument(
        "--threads", type=int, default=None,
        help="Worker thread count (default: min(8, CPU count))",
    )
    parser.add_argument(
        "--recursive", action="store_true",
        help="Include subdirectories when scanning *.json",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Emit structured JSON progress logs to stderr",
    )
    parser.add_argument(
        "--gzip", action="store_true",
        help="Gzip outputs written to files",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # Accept either a directory or a single file
    input_path = Path(args.profiles_dir)
    if not input_path.exists():
        print(f"Error: path not found: {input_path}", file=sys.stderr)
        return 2
    if input_path.is_file():
        profiles_dir = input_path.parent
        explicit_files = [input_path]
    elif input_path.is_dir():
        profiles_dir = input_path
        explicit_files = None
    else:
        print(f"Error: not a file or directory: {input_path}", file=sys.stderr)
        return 2

    # Resolve reference profile
    if args.reference_path:
        ref_path = Path(args.reference_path)
        ref_data, ref_err = _load_json(ref_path)
        ref_file = ref_path.name
        if ref_data is None or not is_valid(ref_data)[0]:
            print(
                f"Error: failed to load reference profile {ref_path}: {ref_err or 'invalid'}",
                file=sys.stderr,
            )
            return 4
    else:
        ref_file = f"DEFAULT-{args.reference}.json"
        ref_data = resolve_default_profile(args.reference, offline=args.offline)
        if ref_data is None or not is_valid(ref_data)[0]:
            print(
                f"Error: could not resolve default profile for '{args.reference}'. "
                "Check network access or supply --reference-path.",
                file=sys.stderr,
            )
            return 4

    # Memoize reference states + risk (loaded once)
    ref_states, ref_risk = reference_states_and_risk(ref_data)
    ref_names = _all_syscall_names(ref_data)

    # Discover files
    if explicit_files is not None:
        files = explicit_files
    else:
        glob_pattern = "**/*.json" if args.recursive else "*.json"
        resolved_base = profiles_dir.resolve()
        files = sorted(
            f for f in profiles_dir.glob(glob_pattern)
            if f.resolve().is_relative_to(resolved_base) and not f.is_symlink()
        )

    # Thread count
    cpu_count = os.cpu_count() or 1
    n_threads = args.threads if args.threads else min(8, cpu_count)

    # Process files concurrently
    all_results: list[dict] = [None] * len(files)  # type: ignore[list-item]

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        futures = {
            pool.submit(_process_file, f, ref_states, ref_risk, ref_names, args.verbose): i
            for i, f in enumerate(files)
        }
        for future in as_completed(futures):
            idx = futures[future]
            all_results[idx] = future.result()

    # Aggregate counts
    total = len(all_results)
    skipped_invalid = sum(1 for r in all_results if r["_skipped"] == "invalid")
    skipped_default = sum(1 for r in all_results if r["_skipped"] == "default_copy")
    analyzed = total - skipped_invalid - skipped_default

    summary = {
        "totalScanned": total,
        "skippedInvalid": skipped_invalid,
        "skippedDefaultCopies": skipped_default,
        "analyzed": analyzed,
    }

    # Build full report
    report = build_report(
        profiles=all_results,
        summary=summary,
        reference_runtime=args.reference,
        reference_profile=ref_file,
    )

    # Determine formats
    formats = args.formats or ["json"]
    out_base = Path(args.out) if args.out else None

    for fmt in formats:
        if fmt == "json":
            if args.split and out_base:
                write_json_split(report, out_base, args.gzip)
            else:
                write_json(report, out_base, args.gzip)
        elif fmt == "ndjson":
            out_path = out_base.parent / (out_base.stem + ".ndjson") if out_base else None
            write_ndjson(all_results, report, out_path, args.gzip)
        elif fmt == "csv":
            out_path = out_base.parent / (out_base.stem + ".csv") if out_base else None
            write_csv(all_results, out_path, args.gzip)

    return 0


if __name__ == "__main__":
    sys.exit(main())
