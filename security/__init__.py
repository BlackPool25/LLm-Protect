"""
Security layer for LLM-Protect.

Provides comprehensive threat detection including:
- Steganography detection
- Unicode threat analysis
- Emoji risk assessment
- Anomaly detection
- Security guard system (main API)
"""

# Main guard system API
from .guard.guard_service import guard_request
from .core.types import IncomingRequest, GuardResult, GuardAction

# Legacy exports (existing security modules)
from .detectors.steganography import SteganographyDetector
from .detectors.unicode_analysis import UnicodeThreatAnalyzer
from .analyzers.semantic_conflict import SemanticConflictDetector
from .analyzers.behavioral import BehavioralAnalyzer

__all__ = [
    # Guard system (new)
    "guard_request",
    "IncomingRequest",
    "GuardResult",
    "GuardAction",
    
    # Legacy modules
    "SteganographyDetector",
    "UnicodeThreatAnalyzer",
    "SemanticConflictDetector",
    "BehavioralAnalyzer",
]
