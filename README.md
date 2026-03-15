# seccompute

Seccomp profile hardening score engine. Scores OCI seccomp profiles 0-100 where 100 = maximally hardened.

See `seccompute/__init__.py` for public API.

## Install

```bash
pip install git+https://github.com/antitree/seccompute@v2.0.0
```

## Usage

```bash
seccompute profile.json
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
```
