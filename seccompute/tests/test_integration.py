"""Integration tests: public API shape, CLI invocation, ScoringResult contract."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Public API import
# ---------------------------------------------------------------------------

def test_public_import():
    """The public API must be importable from seccompute."""
    from seccompute import score_profile, ScoringResult
    assert callable(score_profile)
    assert ScoringResult is not None


def test_score_profile_returns_scoring_result():
    """score_profile() must return a ScoringResult instance."""
    from seccompute import score_profile, ScoringResult
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
    result = score_profile(profile)
    assert isinstance(result, ScoringResult)


def test_scoring_result_has_all_fields():
    """ScoringResult must have: score, tier_breakdown, syscall_details,
    conditionals, warnings, metadata."""
    from seccompute import score_profile, ScoringResult
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
    result = score_profile(profile)

    assert isinstance(result.score, int)
    assert 0 <= result.score <= 100
    assert isinstance(result.tier_breakdown, dict)
    assert isinstance(result.syscall_details, list)
    assert isinstance(result.conditionals, list)
    assert isinstance(result.warnings, list)
    assert isinstance(result.metadata, dict)


def test_scoring_result_to_dict():
    """ScoringResult should be serializable to a dict for JSON output.

    Note: tier_breakdown contains TierScore dataclasses which are not
    directly JSON-serializable. The CLI's _serialize_result handles this.
    """
    from seccompute import score_profile
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
    result = score_profile(profile)
    # Primitive fields should be directly serializable
    d = {
        "score": result.score,
        "warnings": result.warnings,
        "metadata": result.metadata,
    }
    json_str = json.dumps(d)
    assert '"score"' in json_str
    assert result.score == 100


# ---------------------------------------------------------------------------
# CLI invocation
# ---------------------------------------------------------------------------

_PROFILES_DIR = Path(__file__).parent.parent.parent / "app" / "static" / "profiles"


def test_cli_with_profile_json(tmp_path):
    """python -m seccompute <profile.json> should output JSON to stdout."""
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
    profile_path = tmp_path / "test.json"
    profile_path.write_text(json.dumps(profile))

    result = subprocess.run(
        [sys.executable, "-m", "seccompute", str(profile_path)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent.parent),
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert "score" in output
    assert output["score"] == 100


def test_cli_with_docker_default():
    """CLI should work with the Docker default profile."""
    docker_path = _PROFILES_DIR / "DEFAULT-docker.json"
    if not docker_path.exists():
        pytest.skip("Docker default profile not found")

    result = subprocess.run(
        [sys.executable, "-m", "seccompute", str(docker_path)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent.parent),
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert 0 <= output["score"] <= 100


def test_cli_text_format(tmp_path):
    """--format text should produce human-readable output."""
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
    profile_path = tmp_path / "test.json"
    profile_path.write_text(json.dumps(profile))

    result = subprocess.run(
        [sys.executable, "-m", "seccompute", str(profile_path), "--format", "text"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent.parent),
    )
    assert result.returncode == 0
    assert "Score:" in result.stdout or "score" in result.stdout.lower()


def test_cli_invalid_file():
    """CLI with nonexistent file should exit with code 1."""
    result = subprocess.run(
        [sys.executable, "-m", "seccompute", "/nonexistent/file.json"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent.parent),
    )
    assert result.returncode == 1


def test_cli_verbose_flag(tmp_path):
    """--verbose should produce extra output on stderr."""
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [
        {"names": ["bpf"], "action": "SCMP_ACT_ALLOW"}
    ]}
    profile_path = tmp_path / "test.json"
    profile_path.write_text(json.dumps(profile))

    result = subprocess.run(
        [sys.executable, "-m", "seccompute", str(profile_path), "--verbose"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent.parent),
    )
    assert result.returncode == 0
    assert len(result.stderr) > 0


def test_cli_arch_flag(tmp_path):
    """--arch should be accepted and reflected in metadata."""
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}
    profile_path = tmp_path / "test.json"
    profile_path.write_text(json.dumps(profile))

    result = subprocess.run(
        [sys.executable, "-m", "seccompute", str(profile_path),
         "--arch", "SCMP_ARCH_AARCH64"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent.parent),
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["metadata"]["arch"] == "SCMP_ARCH_AARCH64"


def test_cli_warnings_exit_code_2(tmp_path):
    """Profile with unknown syscalls should exit with code 2 (warnings)."""
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [
        {"names": ["totally_fake_syscall"], "action": "SCMP_ACT_ALLOW"}
    ]}
    profile_path = tmp_path / "test.json"
    profile_path.write_text(json.dumps(profile))

    result = subprocess.run(
        [sys.executable, "-m", "seccompute", str(profile_path)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent.parent),
    )
    assert result.returncode == 2
