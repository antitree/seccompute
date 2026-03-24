"""Seccomp profile scoring engine.

Public API:
    from seccompute import score_profile, ScoringResult
    result = score_profile(profile_dict)
    print(result.score)       # 0-100
    print(result.to_json())   # stable JSON
"""

from .model import ScoringResult
from .scoring import score_profile

__all__ = ["score_profile", "ScoringResult"]
