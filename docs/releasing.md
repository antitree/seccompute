# Releasing

Releases are published to [PyPI](https://pypi.org/project/seccompute/) automatically via GitHub Actions when a version tag is pushed.

1. Bump the version in `pyproject.toml`
2. Commit and tag:
   ```bash
   git tag v<version>
   git push origin main v<version>
   ```
3. The `release.yml` workflow builds and publishes to PyPI using [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (no API token required).

## One-time PyPI Setup

Configure a Trusted Publisher at `https://pypi.org/manage/project/seccompute/settings/publishing/` with:
- Owner: `antitree`
- Repository: `seccompute`
- Workflow: `release.yml`
- Environment: `pypi`

Also create a `pypi` environment in the GitHub repo settings.
