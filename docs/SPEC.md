# seccompute Specification v1.0

## Purpose

seccompute scores a Linux seccomp profile on a **0--100 hardening scale** where 0 is the worst (no hardening) and 100 is the best (fully hardened). It detects dangerous individual syscalls, dangerous *combinations* of syscalls, and conditional rule patterns, producing actionable findings with exploit-path descriptions.

## Public API

The package exposes exactly two symbols:

```python
from seccompute import score_profile, ScoringResult
```

### `score_profile(profile, *, arch="SCMP_ARCH_X86_64", rules_dir=None) -> ScoringResult`

Score a normalized seccomp profile dict.

| Parameter   | Type            | Description |
|-------------|-----------------|-------------|
| `profile`   | `dict`          | A **normalized** OCI seccomp profile (see Input Formats). If passing a Kubernetes CRD, normalize it first via `seccompute.normalizer.normalize`. |
| `arch`      | `str`           | Target architecture string. Stored in metadata, does not affect scoring. |
| `rules_dir` | `str` or `None` | Path to a directory containing rule YAML overrides. `None` uses built-in rules. Also overridable via `SECCOMPUTE_RULES_DIR` env var (parameter takes precedence). |

The function is **pure** and **thread-safe**: no global mutable state, no I/O beyond reading YAML rule files (which are cached per `rules_dir` value).

### `ScoringResult`

A frozen dataclass with the following fields:

| Field                  | Type                      | Description |
|------------------------|---------------------------|-------------|
| `score`                | `int`                     | Hardening score, 0--100. |
| `grade`                | `str`                     | Letter grade: A, B, C, D, or F. |
| `forced_failure`       | `bool`                    | True if a forced-failure condition was triggered. |
| `forced_failure_reasons` | `list[str]`             | Human-readable reasons (one per triggering syscall). |
| `annotation_overrides` | `list[str]`               | Syscalls whose forced-failure was lifted by annotation. |
| `scoring_mode`         | `str`                     | Always `"standard"` in v1.0. |
| `tier_summary`         | `dict[str, int]`          | `{"t1_exposed": N, "t2_exposed": N, "t3_exposed": N}` |
| `tier_findings`        | `list[TierFinding]`       | Per-syscall findings for dangerous syscalls that are exposed. |
| `combo_findings`       | `list[ComboFinding]`      | Triggered combo rules. |
| `conditional_findings` | `list[ConditionalFinding]` | Conditional rules that fired. |
| `warnings`             | `list[str]`               | Informational warnings (unknown syscalls, etc.). |
| `metadata`             | `dict[str, Any]`          | `engine_version`, `arch`, `schema_version`, `rules_dir`. |

#### `ScoringResult.to_json() -> str`

Returns a stable JSON string conforming to the JSON Output Schema below.

#### `ScoringResult.to_dict() -> dict`

Returns the dict that `to_json()` serializes.

### Supporting dataclasses

#### `TierFinding`

| Field         | Type        | Description |
|---------------|-------------|-------------|
| `syscall`     | `str`       | Syscall name. |
| `tier`        | `int`       | 1, 2, or 3. |
| `state`       | `str`       | `"allowed"`, `"conditional"`, or `"blocked"`. |
| `weight`      | `float`     | Points at stake for this syscall. |
| `deduction`   | `float`     | Points actually deducted. |
| `description` | `str`       | What this syscall does and why it is dangerous. |
| `exploit_paths` | `list[str]` | Known exploit techniques or CVEs. |

#### `ComboFinding`

| Field              | Type        | Description |
|--------------------|-------------|-------------|
| `id`               | `str`       | Rule ID (e.g., `COMBO-io-uring-network-bypass`). |
| `name`             | `str`       | Human-readable name. |
| `description`      | `str`       | What the combination enables. |
| `severity`         | `str`       | `HIGH`, `MEDIUM`, or `LOW`. |
| `triggered_by`     | `list[str]` | Syscalls from the rule that were found allowed/conditional. |
| `bypasses_blocked` | `list[str]` | Blocked syscalls that are now reachable. |
| `references`       | `list[str]` | CVE IDs, technique IDs, or URLs. |

#### `ConditionalFinding`

| Field            | Type    | Description |
|------------------|---------|-------------|
| `syscall`        | `str`   | Syscall name. |
| `condition_type` | `str`   | One of: `capability_gate`, `argument_filter`, `kernel_version_gate`, `arch_filter`, `deny_with_cap_exclude`. |
| `details`        | `str`   | Human-readable description. |
| `rule_action`    | `str`   | Original seccomp action. |

---

## JSON Output Schema

`schema_version` is `"1.0"`. The output of `ScoringResult.to_json()`:

```json
{
  "schema_version": "1.0",
  "score": 42,
  "grade": "F",
  "forced_failure": true,
  "forced_failure_reasons": ["ptrace allowed unconditionally (T1 catastrophic)"],
  "annotation_overrides": [],
  "scoring_mode": "standard",
  "tier_summary": {
    "t1_exposed": 2,
    "t2_exposed": 5,
    "t3_exposed": 3
  },
  "tier_findings": [
    {
      "syscall": "ptrace",
      "tier": 1,
      "state": "allowed",
      "weight": 9.44,
      "deduction": 9.44,
      "description": "Trace/control another process...",
      "exploit_paths": ["CVE-2019-13272", "TECHNIQUE-container-escape-ptrace"]
    }
  ],
  "combo_findings": [
    {
      "id": "COMBO-io-uring-network-bypass",
      "name": "io_uring network bypass",
      "description": "...",
      "severity": "HIGH",
      "triggered_by": ["io_uring_setup", "io_uring_enter"],
      "bypasses_blocked": ["socket", "connect"],
      "references": ["CVE-2023-2598"]
    }
  ],
  "conditional_findings": [
    {
      "syscall": "clone",
      "condition_type": "argument_filter",
      "details": "Allowed with argument filter (1 conditions)",
      "rule_action": "SCMP_ACT_ALLOW"
    }
  ],
  "warnings": ["Unknown syscall 'foo_bar' not in rules"],
  "metadata": {
    "engine_version": "3.0.0",
    "arch": "SCMP_ARCH_X86_64",
    "schema_version": "1.0",
    "rules_dir": null
  }
}
```

All fields shown above are **required** in every output. Lists may be empty but must be present.

---

## Input Formats

Two formats are supported, auto-detected without a `--format` flag.

### OCI seccomp JSON

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]
}
```

### Kubernetes Security Profiles Operator CRD

Detected by presence of `kind: SeccompProfile` or `apiVersion` containing `security-profiles-operator`.

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
    - action: SCMP_ACT_ALLOW
      names: [read, write]
```

### Normalization

`seccompute.normalizer.normalize(data: dict) -> dict` converts either format into the OCI JSON structure. It extracts `x-seccompute` annotations from both formats. It raises `ValueError` on unrecognizable input.

---

## Scoring Algorithm

### Tier System

Syscalls are classified into three severity tiers with fixed point budgets that sum to 100:

| Tier | Budget | Description | Examples |
|------|--------|-------------|----------|
| T1   | 85     | Catastrophic: kernel code exec, container escape | `bpf`, `ptrace`, `kexec_load`, `init_module` |
| T2   | 10     | Serious: namespace/filesystem escape, large attack surface | `mount`, `setns`, `io_uring_setup`, `keyctl` |
| T3   | 5      | Elevated: contextual risk, DoS, info disclosure | `clone`, `reboot`, `sethostname`, `syslog` |

**Per-syscall weight** = `tier_budget / count(syscalls_in_tier)`.

### Effective State Resolution

For each dangerous syscall, determine its effective state by scanning all profile rules:

1. **Unconditional ALLOW** (no args, no includes, no excludes with permissive action) => `"allowed"` (multiplier 1.0)
2. **Conditional ALLOW** (permissive action with args, includes.caps, includes.minKernel, or includes.arches) => `"conditional"` (multiplier 0.5, except T1 conditional = 0.75)
3. **Deny with cap exclude** (blocking action with excludes.caps) => `"conditional"` (multiplier 0.5) -- bypass possible when process holds the cap
4. **Deny with only arg filters** => `"blocked"` (tightens the block)
5. **Unconditional DENY** => `"blocked"` (multiplier 0.0)
6. **No explicit rule** => falls back to `defaultAction`:
   - `SCMP_ACT_ALLOW`, `SCMP_ACT_LOG`, `SCMP_ACT_TRACE` => `"allowed"`
   - All others => `"blocked"`

When multiple rules mention the same syscall, the **most permissive interpretation wins**: unconditional allow > conditional > unconditional block > default.

### Score Calculation

```
deduction = sum(weight * multiplier for each dangerous syscall)
score = clamp(round(100 - deduction), 0, 100)
```

T1 conditional multiplier exception: in standard mode, T1 syscalls with conditional state use 0.75 instead of 0.5, reflecting that conditionally-available T1 syscalls are still very dangerous.

### Unknown Syscalls

Syscalls present in the profile but not in any rules file and not in the known-safe syscall list generate a warning. Unknown syscalls that are effectively allowed are scored conservatively as T2-equivalent.

---

## Grading

| Grade | Score Range |
|-------|-------------|
| A     | 90--100     |
| B     | 80--89      |
| C     | 70--79      |
| D     | 60--69      |
| F     | 0--59 OR forced-failure |

---

## Forced-Failure Conditions

A profile receives **forced failure** (grade = F regardless of numeric score) when any **Tier 1** syscall is in the `"allowed"` state (unconditional allow). Specifically:

- The syscall must be tier 1.
- The effective state must be `"allowed"` (not `"conditional"`).
- The syscall must NOT be overridden by an annotation (see below).

When forced failure triggers:
- `ScoringResult.forced_failure` is `True`.
- `ScoringResult.grade` is `"F"`.
- `ScoringResult.forced_failure_reasons` lists each triggering syscall with a human-readable reason.
- The numeric `score` is NOT changed by forced failure.

---

## Developer Annotations (`x-seccompute`)

Profiles may include an `x-seccompute` key with developer justifications:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [...],
  "x-seccompute": {
    "intent": {
      "description": "Node.js web server",
      "syscalls": {
        "ptrace": {
          "justification": "Required for Node.js inspector protocol",
          "confined": false
        }
      }
    }
  }
}
```

### Override Behavior

When a T1 syscall has a `justification` string (non-empty) under `x-seccompute.intent.syscalls.<name>`:
- Forced-failure is **lifted** for that specific syscall.
- The syscall name appears in `ScoringResult.annotation_overrides`.
- The **numeric score is NOT changed**. The annotation only affects the forced-failure verdict.
- The justification text appears in the JSON output under `tier_findings[].justification`.

If some T1 syscalls are annotated but others are not, forced-failure remains active for the unannotated ones.

---

## Combo Detection System

Combo rules detect emergent risks where two or more allowed syscalls together enable an attack that neither could achieve alone.

### Combo Rule Format (`combo_rules.yaml`)

```yaml
combos:
  - id: "COMBO-io-uring-network-bypass"
    name: "io_uring network bypass"
    description: "io_uring_enter can perform network I/O..."
    syscalls: ["io_uring_setup", "io_uring_enter"]
    trigger: "all_allowed"    # all_allowed | any_allowed | gate_allowed
    bypasses: ["socket", "connect", "bind", "accept", ...]
    bypass_requires_blocked: true
    severity: "HIGH"
    references: ["CVE-2023-2598"]
```

### Trigger Modes

| Mode            | Fires when... |
|-----------------|---------------|
| `all_allowed`   | ALL syscalls in `syscalls[]` are allowed or conditional |
| `any_allowed`   | ANY syscall in `syscalls[]` is allowed or conditional |
| `gate_allowed`  | The first syscall in `syscalls[]` (the "gate") is allowed or conditional |

### `bypass_requires_blocked`

When `true`, the combo only fires if at least one syscall in `bypasses[]` is effectively blocked. This prevents false positives when the profile is permissive enough that there is nothing to bypass.

---

## Conditional Rule System

Conditional rules (`conditional_rules.yaml`) fire when a syscall is present with specific argument filters or capability gates, providing additional context about *how* a syscall is gated.

```yaml
conditionals:
  - syscall: "clone"
    condition: "argument_filter"
    description: "clone with CLONE_NEWUSER flag creates user namespaces"
    check: "arg_filter_present"
```

These produce `ConditionalFinding` entries in the output. They do not affect the numeric score (the state resolution already accounts for conditionals in the multiplier). They exist purely for informational value.

---

## Rules File Format

All rule files are YAML, loaded with `yaml.safe_load`. No Python is required to edit them.

### `syscall_rules.yaml` -- Tier Classification

```yaml
bpf:
  tier: 1
  category: "process_inspection"
  description: "Load and interact with eBPF programs..."
  threats:
    - id: "CVE-2021-3490"
      description: "eBPF ALU32 bounds tracking OOB write"
    - id: "TECHNIQUE-bpf-kernel-exec"
      description: "Load eBPF to read/write arbitrary kernel memory"
  last_reviewed: "2025-01-15"
```

Required fields per entry: `tier` (int 1-3), `category` (str), `description` (str), `threats` (list of `{id, description}`).

### `combo_rules.yaml` -- Combination Detection

Structure documented in the Combo Detection section above.

### `conditional_rules.yaml` -- Conditional Context

Informational rules. Structure documented in the Conditional Rule section above.

### User-Supplied Rule Overrides

Set `SECCOMPUTE_RULES_DIR=/path/to/rules/` or pass `rules_dir="/path/to/rules/"` to `score_profile`. Files in the override directory replace the corresponding built-in files by name. Missing files fall back to built-in defaults.

### Validation

The rules loader validates YAML structure on load:
- `syscall_rules.yaml`: each entry must have `tier` (int), `category` (str), `description` (str).
- `combo_rules.yaml`: must have top-level `combos` list; each entry must have `id`, `syscalls` (non-empty list), `trigger`, `severity`.
- `conditional_rules.yaml`: must have top-level `conditionals` list.

Malformed input raises `ValueError` with a clear message identifying the problem.

---

## Extension Points

### Adding New Rule Categories

1. Add entries to `syscall_rules.yaml` with the new category string. No code changes needed.
2. Add combo rules to `combo_rules.yaml` if the new category introduces emergent risks.
3. Add conditional rules to `conditional_rules.yaml` if relevant.

The scoring engine dynamically reads all entries from the YAML; it does not hardcode category names.

### Adding New Tiers

Tier definitions (budget allocations and member lists) are derived from `syscall_rules.yaml` entries. To add a Tier 4:
1. Add entries with `tier: 4` to `syscall_rules.yaml`.
2. Define `TIER4_BUDGET` in the tiers module.
3. Adjust existing budgets so all tiers sum to 100.

### Visualization Renderers

`seccompute.viz` defines a `Renderer` protocol:

```python
class Renderer(Protocol):
    def render(self, result: ScoringResult) -> str: ...
```

Built-in: `TerminalRenderer`. Extension point for `HTMLRenderer`, `SVGRenderer`, etc. The viz module operates solely on `ScoringResult` objects and the stable JSON output.

---

## CLI (`python -m seccompute`)

```
usage: seccompute [-h] [--arch ARCH] [--format {json,text}]
                  [--min-score N] [--grade] [--verbose]
                  PROFILE
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Parse error, file not found, or runtime error |
| 2    | Score below `--min-score N` threshold |

Without `--min-score`, the exit code is 0 on success and 1 on error. Warnings do NOT change the exit code (they appear in JSON output).

### Flags

| Flag             | Description |
|------------------|-------------|
| `--arch ARCH`    | Target architecture (default: `SCMP_ARCH_X86_64`) |
| `--format json`  | JSON output (default) |
| `--format text`  | Human-readable text output |
| `--min-score N`  | Exit code 2 if score < N |
| `--grade`        | Show graded visualization with letter grade |
| `--verbose`      | Per-syscall details to stderr |

### Input Auto-Detection

The CLI reads the file, attempts JSON parse first, then YAML parse. It then calls `normalize()` to convert to OCI format. No `--format` flag for input.

---

## Security Requirements

- No `eval`, `exec`, or dynamic code execution.
- No `shell=True` in subprocess calls.
- YAML loaded with `yaml.safe_load` only.
- No pickle or shelve.
- File paths validated before opening (no path traversal: reject paths containing `..`).
- Rules loader validates YAML structure; malformed input raises `ValueError`.

---

## Thread Safety and Web Readiness

- No global mutable state (rule caches are keyed by `rules_dir` and are safe for concurrent reads).
- No `sys.exit` outside `__main__.py`.
- No `print` outside `__main__.py` and `viz`.
- `score_profile` is pure and thread-safe.

---

## Package Structure

```
seccompute/
  __init__.py          # exports: score_profile, ScoringResult only
  __main__.py          # CLI entry point; imports viz lazily
  scoring.py           # orchestrates scoring pipeline
  model.py             # ScoringResult, TierFinding, ComboFinding, ConditionalFinding
  rules.py             # rules loader and validator
  tiers.py             # tier classification and weight computation
  combos.py            # combo detection logic
  conditionals.py      # conditional rule analysis
  normalizer.py        # OCI JSON + K8s CRD -> internal representation
  grader.py            # score -> letter grade, forced-failure logic
  viz.py               # terminal visualization (lazy import only)
  rules/
    syscall_rules.yaml
    combo_rules.yaml
    conditional_rules.yaml
pyproject.toml
tests/
  test_scoring.py
  test_combos.py
  test_conditionals.py
  test_normalizer.py
  test_grader.py
  test_rules.py
  test_cli.py
  conftest.py
docs/
  SPEC.md
  CHANGES.md
```
