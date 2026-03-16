# seccompute

Seccomp profile hardening score engine. Scores OCI seccomp profiles 0-100 where 100 = maximally hardened.

See `seccompute/__init__.py` for public API.

## Install

```bash
pip install seccompute
```

Or from a specific tag:

```bash
pip install git+https://github.com/antitree/seccompute@v2.0.1
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

## Releasing

Releases are published to [PyPI](https://pypi.org/project/seccompute/) automatically via GitHub Actions when a version tag is pushed.

1. Bump the version in `pyproject.toml`
2. Commit and tag:
   ```bash
   git tag v<version>
   git push origin main v<version>
   ```
3. The `release.yml` workflow builds and publishes to PyPI using [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (no API token required).

**One-time PyPI setup:** Configure a Trusted Publisher at `https://pypi.org/manage/project/seccompute/settings/publishing/` with owner `antitree`, repository `seccompute`, workflow `release.yml`, environment `pypi`. Also create a `pypi` environment in the GitHub repo settings.

## Docs & Demos

- Docs live in `docs/` with static assets under `docs/assets/` (logo in `docs/assets/images/logo.svg`).
- Place runnable examples in `demos/` (e.g., `notebooks/`, `cli-examples/`, `profiles/`).
