# seccompute

Seccomp profile hardening score engine. Scores OCI seccomp profiles 0–100 where 100 = maximally hardened.

## Quickstart

```python
from seccompute import score_profile

profile = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [
        {"names": ["read", "write", "exit"], "action": "SCMP_ACT_ALLOW"}
    ]
}

result = score_profile(profile)
print(result.score)        # e.g. 82
print(result.summary)      # human-readable breakdown
```

Or score a profile file from the CLI:

```bash
seccompute profile.json
```

## Install

```bash
pip install seccompute
```

## Combo Bypass Visualization

When a profile allows syscall combinations that bypass seccomp restrictions, seccompute renders ANSI-colored attack chain diagrams showing the bypass path, attack vector, and remediation steps:

```bash
seccompute profile.json
```

Run `python examples/viz_demo.py` to preview visualization styles.
## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## Docs

- API reference and examples: `docs/`
- Release process: `docs/releasing.md`
- Example profiles: `examples/`
