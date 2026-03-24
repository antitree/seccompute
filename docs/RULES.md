# Rules Reference

Seccompute's scoring is entirely driven by three YAML files. You can override any or all of them without touching the source code.

## Rule files

| File | Purpose |
|------|---------|
| `syscall_rules.yaml` | Tier assignment and threat data for individual syscalls |
| `combo_rules.yaml` | Emergent risks from syscall *combinations* (e.g. io_uring bypass chains) |
| `conditional_rules.yaml` | Informational context for syscalls that appear with argument filters |

The built-in rules live at `seccompute/rules/` inside the package. You never need to edit them directly — use the override mechanisms below instead.

---

## Overriding rules

### CLI

Pass a directory with `--rules`. Any file present in that directory overrides the corresponding built-in; missing files fall back to the built-in automatically.

```bash
seccompute profile.json --rules /path/to/my-rules/
```

The directory must contain at least one of the three rule files. It is validated as a directory (not a file path) at startup.

You can also set the directory via environment variable, which is useful in CI:

```bash
export SECCOMPUTE_RULES_DIR=/path/to/my-rules
seccompute profile.json
```

### Python API

Pass `rules_dir` to `score_profile`:

```python
from seccompute import score_profile

result = score_profile(profile, rules_dir="/path/to/my-rules")
```

Same fallback behavior applies — any file absent from your directory uses the built-in.

---

## syscall_rules.yaml

Controls the tier assignment for individual syscalls. Tier determines both severity and how many points are deducted when the syscall is exposed.

**Tier budgets** (total deduction points allocated per tier):

| Tier | Budget | Use for |
|------|--------|---------|
| 1 | 85 pts | Catastrophic: kernel code exec, container escape |
| 2 | 10 pts | High: significant kernel attack surface |
| 3 | 5 pts | Medium: meaningful but bounded risk |

The per-syscall weight is `budget / count(syscalls in tier)`. A profile exposing any T1 syscall unconditionally receives a forced **F** grade regardless of total score.

**Entry format:**

```yaml
syscall_name:
  tier: 1                          # integer, 1–3
  category: "kernel_module"        # string, for grouping in output
  description: "What this syscall does and why it's dangerous."
  threats:
    - id: "CVE-2021-3490"
      description: "Short description of the CVE or technique"
    - id: "TECHNIQUE-bpf-kernel-exec"
      description: "Technique description"
  last_reviewed: "2025-01-15"      # optional, ISO date
```

**To re-tier a syscall** (e.g. demote `clone` from T3 to not scored):

```yaml
# my-rules/syscall_rules.yaml — copy the full built-in, then change the entry
clone:
  tier: 3
  category: "process"
  description: "clone — adjusted weight for our environment"
  threats: []
```

To remove a syscall from scoring entirely, omit it from your override file. Any syscall not present in the loaded rules is silently ignored.

---

## combo_rules.yaml

Detects emergent risk from syscall *combinations*. A combo fires when the trigger condition is met and produces a finding in the output. Combos do **not** affect the numeric score — they are advisory.

**Entry format:**

```yaml
combos:
  - id: "COMBO-io-uring-network-bypass"   # unique, used in output and tests
    name: "io_uring network bypass"        # short human-readable label
    description: >
      Explanation of what the combination enables and why it's dangerous.
    syscalls:                              # syscalls that activate this combo
      - "io_uring_setup"
      - "io_uring_enter"
    trigger: "all_allowed"                 # see trigger modes below
    bypasses:                              # syscalls whose blocks are defeated
      - "socket"
      - "connect"
      - "accept"
    bypass_requires_blocked: true          # only fire if ≥1 bypassed syscall is blocked
    severity: "HIGH"                       # HIGH | MEDIUM | LOW
    references:
      - "TECHNIQUE-io-uring-escape"
      - "CVE-2023-2598"
```

**Trigger modes:**

| Mode | Fires when |
|------|-----------|
| `all_allowed` | Every syscall in `syscalls` is allowed (unconditional or conditional) |
| `any_allowed` | At least one syscall in `syscalls` is allowed |
| `gate_allowed` | First syscall in `syscalls` is allowed (used when one syscall gates the rest) |

**`bypass_requires_blocked: true`** prevents false positives — the combo only fires when the bypass is meaningful (i.e. at least one of the `bypasses` syscalls is actually blocked in the profile). Set to `false` to always fire regardless.

---

## conditional_rules.yaml

Informational annotations for syscalls that appear in the profile with argument filters (`args` field). These produce `ConditionalFinding` entries in the output. They do **not** affect the score — the scoring engine already applies a 0.5× penalty multiplier for conditional syscalls.

**Entry format:**

```yaml
conditionals:
  - syscall: "clone"
    condition: "argument_filter"      # argument_filter | capability_gate
    description: "Explanation of what the condition means and its residual risk."
```

Add an entry here when you want the output to include a note explaining *why* a conditional filter on a particular syscall is or isn't sufficient.

---

## Example: custom rules directory layout

```
my-rules/
├── syscall_rules.yaml      # override tiers for your environment
├── combo_rules.yaml        # add org-specific bypass patterns
└── conditional_rules.yaml  # optional — omit to use built-in
```

Only include the files you want to override. The loader merges per-file, not per-entry — you must include the full file if you override it.
