# seccompute Rebuild Prompt

This is a 1-shot prompt for rebuilding seccompute from the ground up. Feed the
entire `seccompute/` source tree and `tests/` directory as context, then run
this prompt. The agent should produce a specification document first, then
implement against it.

---

## Prompt

You are an expert Python engineer rebuilding **seccompute** — a seccomp profile
hardening assessment tool used by security professionals — from the ground up.
Your output must be clean, minimal, secure, and ready for public release.

### Step 1 — Write the spec first

Before writing any code, produce a file `docs/SPEC.md` that defines:

- The purpose and goals of the tool (derive from the background below)
- The public API surface (`score_profile`, `ScoringResult`, and nothing else)
- The JSON output schema with a `schema_version` field (start at `"1.0"`)
- The rules file format (YAML, human-editable, no Python required)
- The tier classification system and combo detection system
- All forced-failure conditions and how annotation overrides work
- Exit code contract
- Extension points: how new rule categories are added without touching core code

The spec must be complete enough that a different AI could read `docs/SPEC.md`
alone and reimplement the tool correctly.

### Step 2 — Implement against the spec

Build the implementation to satisfy `docs/SPEC.md`. Rules:

- **Reuse existing code only if it is already correct and clean.** Prefer a
  clean rewrite over copying unclear or over-engineered code.
- **Use the existing tests as behavioral contracts**, not as implementation
  guides. Discard any test that validates an internal implementation detail
  rather than an observable behavior specified in `docs/SPEC.md`.
- **Do not add features that are not in the spec.** If something is not in
  `docs/SPEC.md`, do not build it.

---

## Background

### What seccompute does

seccompute scores a seccomp profile on a 0–100 scale where **0 is the worst
(no hardening) and 100 is the best (fully hardened)**. It provides:

- A numeric risk score and a letter grade (standard school thresholds: A ≥ 90,
  B ≥ 80, C ≥ 70, D ≥ 60, F < 60 — no curve)
- Detection of dangerous individual syscalls grouped into severity tiers
- Detection of dangerous *combinations* of syscalls (combo rules) that together
  enable container breakout or privilege escalation even when each syscall alone
  appears acceptable
- Actionable per-finding explanations with exploit path descriptions so
  defenders understand *why* something is flagged, not just *that* it is flagged
- Support for developer annotations that provide context on why a dangerous
  syscall is intentionally allowed — these are embedded in the profile under an
  `x-seccompute` key and can override forced-failure verdicts when explicitly
  justified

The tool is used by:
- **Defenders** building seccomp profiles for containers
- **Offensive researchers** analyzing whether a profile is bypassable
- **CI pipelines** enforcing a minimum score gate on generated profiles

### Forced-failure conditions

Any profile that allows one or more syscalls that are known to enable container
breakout or rootkit-level activity receives an automatic grade of **F**,
regardless of the numeric score. This cannot be overridden by the scoring
weights alone. However, a developer may supply an annotation under
`x-seccompute.intent` that provides a written justification. When a valid
justification is present, the forced-F is lifted and the numeric score is used
for grading. The annotation does not change the numeric score — it only unlocks
the grade.

---

## Architecture constraints

### 1 — Importable core library

The package must be importable as a Python library with zero side effects:

```python
from seccompute import score_profile, ScoringResult
result = score_profile(profile_dict)
print(result.score)        # int, 0–100
print(result.to_json())    # str, stable JSON
```

The library must never import visualization code at the top level. Visualization
is an optional layer loaded only when explicitly requested.

### 2 — Visualization is a separate optional layer

Visualization code lives in `seccompute.viz` and must only be imported
explicitly. It must operate solely on `ScoringResult` objects or the stable
JSON output — it must not reach into scoring internals. Leave extension points
in the viz layer for future HTML/SVG/PNG renderers (a `Renderer` base class or
protocol is sufficient).

### 3 — Rules are human-editable YAML files

All scoring rules live in YAML files that a user can read, edit, and override
without writing Python. Three built-in rule categories are required:

- **Tiers** (`syscall_rules.yaml`) — per-syscall tier classification (T1, T2,
  T3, …) with a description of the risk and known exploit paths
- **Combos** (`combo_rules.yaml`) — named combinations of two or more syscalls
  that together enable a dangerous capability, with severity, description, and
  references
- **Conditionals** (`conditional_rules.yaml`) — rules that fire only when a
  syscall is present *with specific argument filters* (e.g. `ptrace` with
  `PTRACE_POKEDATA`)

The rules loader must support **user-supplied rule file overrides** via an
environment variable (`SECCOMPUTE_RULES_DIR`) or a parameter to `score_profile`.
This lets users extend or replace rules without modifying the installed package.

### 4 — Stable JSON output with schema versioning

The JSON output must include a `schema_version` field. The schema must remain
stable within a major version. Breaking changes require a new major version.
The JSON must be concise — include only data that is actionable or required for
visualization. No redundant fields.

Minimum required fields:

```json
{
  "schema_version": "1.0",
  "score": 42,
  "grade": "F",
  "forced_failure": true,
  "forced_failure_reason": "...",
  "scoring_mode": "standard",
  "tier_summary": { "t1_exposed": 2, "t2_exposed": 5 },
  "combo_findings": [...],
  "tier_findings": [...],
  "conditional_findings": [...],
  "warnings": [...],
  "metadata": { "engine_version": "...", "arch": "..." }
}
```

### 5 — CI integration

The tool must support a `--min-score INT` flag on the CLI. Behavior:

- Without `--min-score`: exit 0 on success, exit 1 on parse/runtime error.
  A profile with critical findings still exits 0 — the findings are in stdout.
- With `--min-score N`: additionally exit 2 if `result.score < N`. This is the
  CI gate signal.

This makes it safe to use in pipelines without `--min-score` (never fails the
build unexpectedly) while giving CI authors an explicit opt-in gate.

### 6 — Input format support

Support two input formats. Auto-detect based on file content (check for
`kind: SeccompProfile` or YAML vs JSON structure). Never require a `--format`
flag — infer it. Fail clearly with a descriptive error message if the format
cannot be determined.

**OCI seccomp JSON** (standard container runtime format):
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [{ "names": ["read"], "action": "SCMP_ACT_ALLOW" }]
}
```

**Kubernetes Security Profiles Operator CRD**
(`security-profiles-operator.x-k8s.io/v1beta1`, kind `SeccompProfile`):
```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: example
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
    - action: SCMP_ACT_ALLOW
      names: [read, write]
```

Both formats must be normalized to a common internal representation before
scoring. The normalizer must be a standalone function so seccompare can call it
directly.

### 7 — Developer annotations (`x-seccompute`)

Profiles may embed an `x-seccompute` block to provide context:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [...],
  "x-seccompute": {
    "intent": {
      "description": "Node.js web server",
      "syscalls": {
        "io_uring": {
          "justification": "Required for libuv async I/O in Node 18+",
          "confined": false
        }
      }
    }
  }
}
```

When a syscall has a justification, forced-failure is lifted for that syscall.
The justification appears in the JSON output and text output so reviewers can
evaluate it. The numeric score is not changed by annotations.

### 8 — Security requirements

- No `eval`, `exec`, or dynamic code execution anywhere
- No shell=True in subprocess calls
- YAML loaded with `yaml.safe_load` only, never `yaml.load`
- No pickle or shelve
- File paths must be validated before opening (no path traversal)
- The rules loader must validate YAML structure and fail with a clear error on
  malformed input — never silently ignore bad rules
- No logging of user-supplied data at DEBUG level in a way that could leak
  sensitive profile contents

### 9 — Future web API readiness

The library must be importable by a Flask app (e.g. seccompare) with no
additional configuration. This means:

- No global mutable state
- No `sys.exit` calls outside `__main__.py`
- No print statements outside `__main__.py` and `viz`
- `score_profile` must be pure and thread-safe: given the same input it returns
  the same output, with no side effects

### 10 — Package structure

```
seccompute/
  __init__.py          # exports: score_profile, ScoringResult only
  __main__.py          # CLI entry point; imports viz lazily
  scoring.py           # orchestrates scoring pipeline
  model.py             # ScoringResult and related dataclasses
  rules.py             # rules loader and validator
  tiers.py             # tier classification logic
  combos.py            # combo detection logic
  conditionals.py      # conditional rule logic
  normalizer.py        # OCI JSON + K8s CRD → internal representation
  grader.py            # score → letter grade, forced-failure logic
  viz.py               # terminal visualization (lazy import only)
  rules/
    syscall_rules.yaml
    combo_rules.yaml
    conditional_rules.yaml
pyproject.toml         # viz and cli optional extras; PyYAML as only hard dep
docs/
  SPEC.md              # generated in Step 1
```

---

## What NOT to build

- No web API, no Flask routes, no HTTP server
- No GitHub Actions workflow files
- No HTML/SVG/PNG renderers (leave the extension point, do not implement)
- No interactive intent collection (the `--interactive` flag from the old CLI)
  unless it is specified in `docs/SPEC.md` after you write it
- No `--save` flag that writes back to the profile file unless specified in the spec
- No features that existed in the old codebase but are not derivable from this
  prompt and the behavioral test contracts

---

## Grading scale

| Grade | Score range |
|-------|-------------|
| A     | 90–100      |
| B     | 80–89       |
| C     | 70–79       |
| D     | 60–69       |
| F     | 0–59 OR forced-failure condition |

A forced-failure overrides any grade above F. A valid annotation justification
lifts the forced-failure, restoring the numeric grade. The forced-failure status
and any active justifications must appear in the JSON output.

---

## Deliverables

1. `docs/SPEC.md` — the complete specification
2. All source files under `seccompute/`
3. Updated `pyproject.toml`
4. A test suite where each test validates a behavioral contract from the spec,
   not an implementation detail
5. A brief `docs/CHANGES.md` noting what was removed from the old implementation
   and why
