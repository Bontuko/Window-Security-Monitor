"""
ProcSentinel Engines Package

Analysis and classification engines:
- severity: Severity classification based on rules
- recommender: Generates explanations and recommendations
"""

from app.engines.severity import classify
from app.engines.recommender import generate_explanation_and_recommendation

__all__ = [
    'classify',
    'generate_explanation_and_recommendation',
]
