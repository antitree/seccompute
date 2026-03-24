"""Behavioral tests for CLI interface per SPEC.md."""
import json
import subprocess
import sys

import pytest

_MINIMAL_PROFILE = json.dumps({
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}],
})

_ALLOW_ALL = json.dumps({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []})

_PTRACE_PROFILE = json.dumps({
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [{"names": ["ptrace"], "action": "SCMP_ACT_ALLOW"}],
})


def _run(args: list[str], input_data: str | None = None, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "seccompute"] + args,
        input=input_data,
        capture_output=True,
        text=True,
        env=env,
    )


class TestCLIBasic:
    def test_stdin_json(self):
        r = _run(["--json"], _MINIMAL_PROFILE)
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert "score" in data
        assert "grade" in data

    def test_file_input(self, tmp_path):
        f = tmp_path / "profile.json"
        f.write_text(_MINIMAL_PROFILE)
        r = _run(["--json", str(f)])
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["score"] >= 0

    def test_json_output_schema(self):
        r = _run(["--json"], _MINIMAL_PROFILE)
        data = json.loads(r.stdout)
        assert data["schema_version"] == "1.0"
        assert "tier_summary" in data
        assert "metadata" in data

    def test_human_output_default(self):
        r = _run([], _MINIMAL_PROFILE)
        assert r.returncode == 0
        assert "Grade" in r.stdout or "score" in r.stdout.lower()


class TestCLIExitCodes:
    def test_exit_0_normal(self):
        r = _run(["--json"], _MINIMAL_PROFILE)
        assert r.returncode == 0

    def test_exit_2_below_threshold(self):
        # allow-all profile scores very low
        r = _run(["--json", "--min-score", "50"], _ALLOW_ALL)
        assert r.returncode == 2

    def test_exit_0_above_threshold(self):
        r = _run(["--json", "--min-score", "50"], _MINIMAL_PROFILE)
        assert r.returncode == 0

    def test_exit_1_bad_input(self):
        r = _run(["--json"], "not json at all")
        assert r.returncode == 1


class TestCLIEdgeCases:
    def test_empty_stdin_fails(self):
        r = _run(["--json"], "")
        assert r.returncode == 1

    def test_nonexistent_file_fails(self):
        r = _run(["--json", "/nonexistent/file.json"])
        assert r.returncode == 1
