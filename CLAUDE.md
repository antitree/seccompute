# seccompute — development instructions

## README maintenance

**Whenever you make any of the following changes, update `README.md` to match:**

- CLI option added, removed, or renamed (`__main__.py` `_parse_args`)
- Python API signature changed (`score_profile`, `ScoringResult`, or anything exported from `__init__.py`)
- New input format supported (e.g. new profile fields, new file types)
- Output format or JSON schema changed
- New environment variable that affects behavior

The CLI reference section in README.md must always reflect the actual `--help` output. When in doubt, run `python -m seccompute --help` and sync the README to match.
