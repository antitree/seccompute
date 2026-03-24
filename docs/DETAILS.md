# Testing / Development

```bash
pip install -e ".[dev]"
pytest -q
```

# Output / Formats

### JSON output (default)

```bash
seccompute profile.json
```

```json
{
  "schema_version": "1.0",
  "score": 98,
  "grade": "A",
  "forced_failure": false,
  "tier_summary": {
    "t1_exposed": 0,
    "t2_exposed": 3,
    "t3_exposed": 0
  },
  "combo_findings": [
    {
      "id": "COMBO-io-uring-network-bypass",
      "name": "io_uring network bypass",
      "severity": "HIGH",
      "triggered_by": ["io_uring_setup", "io_uring_enter"],
      "bypasses_blocked": ["accept", "bind", "connect", "socket", "..."]
    }
  ],
  "tier_findings": [ "..." ],
  "metadata": {
    "engine_version": "3.0.0",
    "arch": "SCMP_ARCH_X86_64"
  }
}
```

### Python API

```python
from seccompute import score_profile

result = score_profile(profile_dict)                        # built-in rules
result = score_profile(profile_dict, rules_dir="./my-rules") # custom rules
result = score_profile(profile_dict, arch="SCMP_ARCH_ARM64")

result.score   # int 0-100
result.grade   # "A" through "F"
result.forced_failure         # bool
result.forced_failure_reasons # list[str]
result.tier_findings          # per-syscall deductions
result.combo_findings         # bypass chain detections
```