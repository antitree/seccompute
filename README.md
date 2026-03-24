# seccompute

Seccomp profile hardening score engine. Scores OCI seccomp profiles 0–100 where 100 = maximally hardened.

## Install

```bash
pip install seccompute
```

## Quickstart

Score a profile file from the CLI:

```bash
seccompute profile.json            # JSON output
seccompute profile.json --grade    # letter-grade visualization
```

Or use the Python API:

```python
from seccompute import score_profile

profile = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [
        {"names": ["read", "write", "exit"], "action": "SCMP_ACT_ALLOW"}
    ]
}

result = score_profile(profile)
print(result.score)   # e.g. 98
print(result.grade)   # e.g. "A"
```

## Output

### `--grade` visualization

The `--grade` flag renders a color-coded hardening report with tier breakdown, combo risks, and exposed syscalls.

**Grade A — tight profile with io_uring bypass risk:**

![Grade A output](docs/grade_a_output.svg)

**Grade F — permissive profile with T1 syscalls exposed:**

![Grade F output](docs/grade_f_output.svg)

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

## Scoring model

| Tier | Examples | Max deduction |
|------|----------|---------------|
| T1 — critical | `bpf`, `ptrace`, `init_module` | 7+ pts each |
| T2 — high | `io_uring_*`, `perf_event_open` | 0.5 pts each |
| T3 — medium | `clone`, `chroot`, `mount` | 0.1–0.2 pts each |

A profile exposing any T1 syscall receives a forced **F** regardless of total score. Combo findings (e.g. io_uring bypass chains) are reported separately and do not affect the numeric score.

## Combo Bypass Detection

When a profile allows syscall combinations that bypass seccomp restrictions, seccompute reports attack chain details — the bypass path, bypassed syscalls, and CVE/technique references:

```
[HIGH] io_uring network bypass: io_uring_setup, io_uring_enter
       bypasses: accept, bind, connect, socket, send, recv, ...
       refs: TECHNIQUE-io-uring-escape, CVE-2023-2598, CVE-2024-0582
```

## CLI reference

```
seccompute [profile] [options]

  --grade           Letter-grade visualization (ANSI color)
  --json            Shorthand for --format json
  --format text     Plain text summary
  --arch ARCH       Target architecture (default: from profile)
  --min-score N     Exit 2 if score < N (use in CI)
  --compare-docker  Show delta vs Docker default seccomp allowlist
  --verbose         Per-syscall details to stderr
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## Docs

- Release process: `docs/releasing.md`
- Example profiles: `examples/`
