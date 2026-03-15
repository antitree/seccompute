# seccompute package
"""Seccomp profile scoring engine.

Public API:
    from seccompute import score_profile, ScoringResult
    result = score_profile(profile_dict)
    print(result.score)  # 0-100
"""

from .scoring import ScoringResult, score_profile

__all__ = ["score_profile", "ScoringResult"]
