"""Behavioral tests for CLI interface per SPEC.md."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

_EXAMPLES = Path(__file__).parent.parent / "examples"

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


class TestYAML:
    _MINIMAL_YAML = """\
defaultAction: SCMP_ACT_ERRNO
syscalls:
  - names: [read, write, exit, exit_group]
    action: SCMP_ACT_ALLOW
"""

    _INVALID_YAML = "defaultAction: [\nunclosed bracket"

    def test_stdin_yaml(self):
        r = _run(["--json"], self._MINIMAL_YAML)
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert "score" in data
        assert "grade" in data

    def test_stdin_yaml_output_schema(self):
        r = _run(["--json"], self._MINIMAL_YAML)
        data = json.loads(r.stdout)
        assert data["schema_version"] == "1.0"
        assert "tier_summary" in data
        assert "metadata" in data

    def test_stdin_invalid_yaml_fails(self):
        r = _run(["--json"], self._INVALID_YAML)
        assert r.returncode == 1

    def test_file_yaml_iouring_bypass(self):
        f = _EXAMPLES / "profile3-network-blocked-iouring-bypass.yaml"
        r = _run(["--json", str(f)])
        assert r.returncode == 0
        data = json.loads(r.stdout)
        combo_ids = [c["id"] for c in data.get("combo_findings", [])]
        assert "COMBO-io-uring-network-bypass" in combo_ids

    def test_file_yaml_ptrace_conditional(self):
        f = _EXAMPLES / "profile5-ptrace-conditional-pid-restriction.yaml"
        r = _run(["--json", str(f)])
        assert r.returncode == 0
        data = json.loads(r.stdout)
        # Conditional ptrace (args filter) is penalized but does not force F
        assert data["score"] < 100
        t1_syscalls = [
            t["syscall"] for t in data.get("tier_findings", []) if t["tier"] == 1
        ]
        assert "ptrace" in t1_syscalls

    def test_yaml_and_json_same_score(self, tmp_path):
        """YAML and JSON representations of the same profile must score identically."""
        json_profile = json.dumps({
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}],
        })
        yaml_profile = "defaultAction: SCMP_ACT_ERRNO\nsyscalls:\n  - names: [read, write]\n    action: SCMP_ACT_ALLOW\n"

        r_json = _run(["--json"], json_profile)
        r_yaml = _run(["--json"], yaml_profile)

        assert r_json.returncode == 0
        assert r_yaml.returncode == 0
        assert json.loads(r_json.stdout)["score"] == json.loads(r_yaml.stdout)["score"]
