"""default_profiles — resolve canonical default seccomp profiles.

Resolution order for each runtime:
  1. Local cache (~/.cache/seccompute/profiles/ or XDG_CACHE_HOME)
  2. seccompare.com API  (GET /api/profiles/default?runtime=<runtime>)
  3. Official upstream source (Moby GitHub for docker, etc.)

The fetched profile is written to the local cache so subsequent calls are fast.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Upstream sources
# ---------------------------------------------------------------------------

_UPSTREAM_URLS: dict[str, str] = {
    "docker": (
        "https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json"
    ),
    "podman": (
        "https://raw.githubusercontent.com/containers/common/main/pkg/seccomp/seccomp.json"
    ),
    "containerd": (
        "https://raw.githubusercontent.com/containerd/containerd/main/contrib/seccomp/seccomp_default.go"
        # containerd embeds its profile in Go source; keep as fallback but may need special handling
    ),
}

_SECCOMPARE_API_URL = "https://seccompare.com/api/profiles/default?runtime={runtime}"

_REQUEST_TIMEOUT = 10  # seconds


# ---------------------------------------------------------------------------
# Cache location
# ---------------------------------------------------------------------------

def _cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME", "")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "seccompute" / "profiles"


def _cache_path(runtime: str) -> Path:
    return _cache_dir() / f"DEFAULT-{runtime}.json"


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------

def _fetch_url(url: str) -> dict | None:
    """Fetch JSON from *url*. Returns parsed dict or None on failure."""
    try:
        with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT) as resp:
            raw = resp.read()
        return json.loads(raw)
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return None


def _fetch_seccompare(runtime: str) -> dict | None:
    """Fetch from seccompare.com API.

    Response shape: {"<runtime>": {<profile>}, "_meta": {...}}
    Extract and return only the profile dict.
    """
    url = _SECCOMPARE_API_URL.format(runtime=runtime)
    resp = _fetch_url(url)
    if resp is None:
        return None
    profile = resp.get(runtime)
    if not isinstance(profile, dict):
        return None
    return profile


def _fetch_upstream(runtime: str) -> dict | None:
    url = _UPSTREAM_URLS.get(runtime)
    if not url:
        return None
    return _fetch_url(url)


# ---------------------------------------------------------------------------
# Cache read / write
# ---------------------------------------------------------------------------

def _read_cache(runtime: str) -> dict | None:
    path = _cache_path(runtime)
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(runtime: str, data: dict) -> None:
    path = _cache_path(runtime)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError:
        pass  # cache write failure is non-fatal


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_default_profile(runtime: str, *, offline: bool = False) -> dict | None:
    """Return the canonical default seccomp profile for *runtime*.

    Resolution order:
      1. Local cache
      2. seccompare.com API        (skipped when *offline* is True)
      3. Official upstream source  (skipped when *offline* is True)

    Returns the parsed JSON dict, or None if unavailable.
    """
    # 1. Local cache
    cached = _read_cache(runtime)
    if cached is not None:
        return cached

    if offline:
        return None

    # 2. seccompare.com API
    data = _fetch_seccompare(runtime)

    # 3. Official upstream
    if data is None:
        data = _fetch_upstream(runtime)

    if data is not None:
        _write_cache(runtime, data)

    return data


def cache_path_for(runtime: str) -> Path:
    """Return the cache path for *runtime* (may or may not exist yet)."""
    return _cache_path(runtime)
