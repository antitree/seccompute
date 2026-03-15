"""Tests for report.py: JSON schema shape, NDJSON structure, CSV fields, split output."""

import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from seccompute.report import build_report, write_csv, write_json, write_ndjson


def _make_profile(filename="test.json", valid=True, delta=10.0, coverage=80.0):
    return {
        "filename": filename,
        "sha256": "abc123",
        "valid": valid,
        "skippedReason": None if valid else "json_error",
        "vsDefaultHardeningDeltaPct": delta,
        "defaultRisk": 100.0,
        "profileRisk": 90.0,
        "vsNoneCoveragePct": coverage,
        "dangerousBlockedCount": 40,
        "dangerousAllowedUnconditionally": ["bpf"],
        "dangerousAllowedConditionally": ["clone"],
        "improvedSyscalls": ["mount"],
        "regressedSyscalls": [],
        "_conditionUsage": {"capInclude": 1, "capExclude": 0, "argFilter": 2, "archInclude": 0, "minKernel": 0},
        "_skipped": None,
    }


def _make_summary(total=5, invalid=1, default_copies=1, analyzed=3):
    return {
        "totalScanned": total,
        "skippedInvalid": invalid,
        "skippedDefaultCopies": default_copies,
        "analyzed": analyzed,
    }


def test_report_summary_fields():
    profiles = [_make_profile(f"p{i}.json") for i in range(3)]
    summary = _make_summary()
    report = build_report(profiles, summary, "docker", "DEFAULT-docker.json")

    s = report["summary"]
    assert s["totalScanned"] == 5
    assert s["skippedInvalid"] == 1
    assert s["skippedDefaultCopies"] == 1
    assert s["analyzed"] == 3
    assert s["referenceRuntime"] == "docker"
    assert s["referenceProfile"] == "DEFAULT-docker.json"
    assert "weightsPack" in s


def test_report_hardening_overview_keys():
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "DEFAULT-docker.json")
    ho = report["hardeningOverview"]
    for key in ("avgDeltaPct", "p50DeltaPct", "p90DeltaPct", "topImprovedProfiles", "topRegressedProfiles"):
        assert key in ho, f"missing key: {key}"


def test_report_top_improved_profiles_capped_at_10():
    profiles = [_make_profile(f"p{i}.json", delta=float(i)) for i in range(20)]
    report = build_report(profiles, _make_summary(total=20, analyzed=20, invalid=0, default_copies=0), "docker", "f")
    assert len(report["hardeningOverview"]["topImprovedProfiles"]) <= 10
    assert len(report["hardeningOverview"]["topRegressedProfiles"]) <= 10


def test_report_vs_none_overview_keys():
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "f")
    vno = report["vsNoneOverview"]
    for key in ("avgCoveragePct", "avgDangerousBlocked", "avgDangerousAllowed"):
        assert key in vno


def test_report_dangerous_reachability_structure():
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "f")
    dr = report["dangerousReachability"]
    for sc, val in dr.items():
        assert "reachableUnconditionally" in val
        assert "reachableConditionally" in val
        assert "blocked" in val


def test_report_profiles_no_internal_keys():
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "f")
    for p in report["profiles"]:
        for key in p:
            assert not key.startswith("_"), f"internal key leaked: {key}"


def test_report_condition_usage_summed():
    p1 = _make_profile("a.json")
    p2 = _make_profile("b.json")
    p2["_conditionUsage"] = {"capInclude": 3, "capExclude": 1, "argFilter": 0, "archInclude": 0, "minKernel": 0}
    report = build_report([p1, p2], _make_summary(analyzed=2), "docker", "f")
    cu = report["conditionUsage"]
    assert cu["capInclude"] == 4   # 1 + 3
    assert cu["capExclude"] == 1
    assert cu["argFilter"] == 2


def test_write_json_stdout(monkeypatch, capsys):
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "f")
    write_json(report, None, False)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert "summary" in parsed


def test_write_json_file(tmp_path):
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "f")
    out = tmp_path / "report.json"
    write_json(report, out, False)
    parsed = json.loads(out.read_text())
    assert "profiles" in parsed


def test_write_ndjson_stdout(capsys):
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "f")
    write_ndjson(profiles, report, None, False)
    captured = capsys.readouterr()
    lines = [l for l in captured.out.strip().split("\n") if l]
    assert len(lines) >= 2  # at least one profile + summary line
    last = json.loads(lines[-1])
    assert last.get("type") == "summary"


def test_write_csv_stdout(capsys):
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "f")
    write_csv(profiles, None, False)
    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    header = lines[0]
    assert "filename" in header
    assert "sha256" in header
    assert "vsDefaultHardeningDeltaPct" in header


def test_write_csv_file(tmp_path):
    profiles = [_make_profile("x.json")]
    report = build_report(profiles, _make_summary(), "docker", "f")
    out = tmp_path / "report.csv"
    write_csv(profiles, out, False)
    text = out.read_text()
    assert "x.json" in text


def test_write_gzip_file(tmp_path):
    import gzip as gz
    profiles = [_make_profile()]
    report = build_report(profiles, _make_summary(), "docker", "f")
    out = tmp_path / "report.json"
    write_json(report, out, use_gzip=True)
    gz_path = Path(str(out) + ".gz")
    assert gz_path.exists()
    with gz.open(gz_path, "rt") as f:
        parsed = json.load(f)
    assert "summary" in parsed
