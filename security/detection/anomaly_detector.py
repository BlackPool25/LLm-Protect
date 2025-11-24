"""
Anomaly detection module for the Security Guard System.

Implements rule-based heuristic anomaly detection with configurable
thresholds. Can be upgraded to ML-based detection (Isolation Forest, LOF)
in the future without changing the interface.
"""

from typing import List, Dict
from security.core.types import (
    FusionFeatures,
    AnomalyDecision,
    Verdict,
)
from security.utils.pattern_matcher import PatternMatcher
from config.security_config import (
    ANOMALY_THRESHOLDS,
    FEATURE_WEIGHTS,
    STEGO_HIGH_THRESHOLD,
    EMOJI_RISK_HIGH_THRESHOLD,
    UNICODE_THREAT_THRESHOLD,
    EMOJI_REPETITION_THRESHOLD,
    PATTERN_COMPLEXITY_THRESHOLD,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# Anomaly Score Computation
# ============================================================================

def compute_anomaly_score(features: FusionFeatures) -> float:
    """
    Compute anomaly score using rule-based heuristics.
    
    Applies weighted scoring based on detected threats:
    - High steganography score
    - High emoji risk score
    - Unicode threats detected
    - Prompt injection patterns
    - Emoji cipher patterns
    
    Args:
        features: Fused features from all pipelines
        
    Returns:
        Anomaly score (0-1), where higher = more anomalous
    """
    score = 0.0
    
    # === Image-based threats ===
    if features.image_features:
        stego_score = features.image_features.stego_score
        
        # High steganography score
        if stego_score > STEGO_HIGH_THRESHOLD:
            contribution = FEATURE_WEIGHTS["stego_score"] * (stego_score - STEGO_HIGH_THRESHOLD) / (1.0 - STEGO_HIGH_THRESHOLD)
            score += contribution
            logger.debug(f"Stego contribution: +{contribution:.3f} (score={stego_score:.3f})")
    
    # === Emoji-based threats ===
    if features.emoji_features:
        emoji_risk = features.emoji_features.emoji_risk_score
        pattern_features = features.emoji_features.pattern_features
        unicode_threats = features.emoji_features.unicode_threats
        
        # High emoji risk score
        if emoji_risk > EMOJI_RISK_HIGH_THRESHOLD:
            contribution = FEATURE_WEIGHTS["emoji_risk_score"] * (emoji_risk - EMOJI_RISK_HIGH_THRESHOLD) / (1.0 - EMOJI_RISK_HIGH_THRESHOLD)
            score += contribution
            logger.debug(f"Emoji risk contribution: +{contribution:.3f} (score={emoji_risk:.3f})")
        
        # Unicode threats
        if unicode_threats.overall_unicode_threat_score > UNICODE_THREAT_THRESHOLD:
            contribution = FEATURE_WEIGHTS["unicode_threats"] * unicode_threats.overall_unicode_threat_score
            score += contribution
            logger.debug(f"Unicode threat contribution: +{contribution:.3f}")
        
        # Emoji cipher pattern
        if pattern_features.cipher_like:
            contribution = FEATURE_WEIGHTS["emoji_cipher"]
            score += contribution
            logger.debug(f"Emoji cipher contribution: +{contribution:.3f}")
        
        # High pattern complexity
        if pattern_features.pattern_complexity > PATTERN_COMPLEXITY_THRESHOLD:
            contribution = 0.2 * pattern_features.pattern_complexity
            score += contribution
            logger.debug(f"Pattern complexity contribution: +{contribution:.3f}")
        
        # Repetition spam
        if pattern_features.repetition_score > EMOJI_REPETITION_THRESHOLD:
            contribution = 0.15 * pattern_features.repetition_score
            score += contribution
            logger.debug(f"Repetition contribution: +{contribution:.3f}")
    
    # Clip to 0-1 range
    score = min(1.0, max(0.0, score))
    
    logger.info(f"Computed anomaly score: {score:.3f}")
    return score


# ============================================================================
# Reason Generation
# ============================================================================

def generate_anomaly_reasons(features: FusionFeatures, score: float) -> List[str]:
    """
    Generate human-readable reasons for anomaly detection.
    
    IMPORTANT: Reasons should be generic and security-conscious.
    Never reveal specific detection logic or thresholds.
    
    Args:
        features: Fused features
        score: Computed anomaly score
        
    Returns:
        List of generic reason strings
    """
    reasons = []
    
    # === Image-based reasons ===
    if features.image_features:
        if features.image_features.stego_score > STEGO_HIGH_THRESHOLD:
            reasons.append("Image contains suspicious patterns")
    
    # === Emoji-based reasons ===
    if features.emoji_features:
        emoji_risk = features.emoji_features.emoji_risk_score
        pattern_features = features.emoji_features.pattern_features
        unicode_threats = features.emoji_features.unicode_threats
        
        # High-risk emoji categories (generic message)
        if emoji_risk > EMOJI_RISK_HIGH_THRESHOLD:
            categories = features.emoji_features.emoji_categories
            # Filter out "unknown" and "neutral"
            risky_categories = [c for c in categories if c not in ["unknown", "neutral"]]
            if risky_categories:
                reasons.append("Content may violate safety guidelines")
        
        # Unicode threats (generic message)
        if unicode_threats.has_zero_width or unicode_threats.has_bidi_override:
            reasons.append("Text contains formatting that cannot be processed")
        
        if unicode_threats.has_homoglyphs:
            reasons.append("Text contains characters that may be misleading")
        
        # Emoji patterns (generic message)
        if pattern_features.cipher_like:
            reasons.append("Content contains unusual patterns")
        
        if pattern_features.repetition_score > EMOJI_REPETITION_THRESHOLD:
            reasons.append("Content appears repetitive or spam-like")
    
    # If no specific reasons but score is high, add generic reason
    if not reasons and score > ANOMALY_THRESHOLDS["borderline"]:
        reasons.append("Content flagged by security analysis")
    
    return reasons


# ============================================================================
# Triggered Rules Tracking
# ============================================================================

def get_triggered_rules(features: FusionFeatures) -> List[str]:
    """
    Get list of specific rules that triggered (for debugging/logging).
    
    These are internal rule names, not shown to users.
    
    Args:
        features: Fused features
        
    Returns:
        List of triggered rule names
    """
    triggered = []
    
    if features.image_features:
        if features.image_features.stego_score > STEGO_HIGH_THRESHOLD:
            triggered.append(f"high_stego_score_{features.image_features.stego_score:.2f}")
    
    if features.emoji_features:
        emoji_risk = features.emoji_features.emoji_risk_score
        pattern_features = features.emoji_features.pattern_features
        unicode_threats = features.emoji_features.unicode_threats
        
        if emoji_risk > EMOJI_RISK_HIGH_THRESHOLD:
            triggered.append(f"high_emoji_risk_{emoji_risk:.2f}")
        
        if unicode_threats.has_zero_width:
            triggered.append(f"zero_width_chars_{unicode_threats.zero_width_count}")
        
        if unicode_threats.has_bidi_override:
            triggered.append(f"bidi_override_{unicode_threats.bidi_override_count}")
        
        if unicode_threats.has_homoglyphs:
            triggered.append(f"homoglyphs_{unicode_threats.homoglyph_count}")
        
        if pattern_features.cipher_like:
            triggered.append("emoji_cipher_pattern")
        
        if pattern_features.repetition_score > EMOJI_REPETITION_THRESHOLD:
            triggered.append(f"emoji_repetition_{pattern_features.repetition_score:.2f}")
    
    return triggered


# ============================================================================
# Verdict Determination
# ============================================================================

def determine_verdict(score: float, thresholds: Dict[str, float] = ANOMALY_THRESHOLDS) -> Verdict:
    """
    Determine verdict from anomaly score.
    
    Args:
        score: Anomaly score (0-1)
        thresholds: Threshold configuration
        
    Returns:
        Verdict (PASS, BORDERLINE, or FAIL)
    """
    if score < thresholds["pass"]:
        return Verdict.PASS
    elif score < thresholds["borderline"]:
        return Verdict.BORDERLINE
    else:
        return Verdict.FAIL


# ============================================================================
# Main Anomaly Detection Function
# ============================================================================

def compute_anomaly_decision(features: FusionFeatures) -> AnomalyDecision:
    """
    Compute complete anomaly detection decision.
    
    Main function that orchestrates:
    1. Anomaly score computation
    2. Reason generation
    3. Verdict determination
    4. Rule tracking
    
    Args:
        features: Fused features from all pipelines
        
    Returns:
        AnomalyDecision with verdict, score, and reasons
        
    Example:
        >>> decision = compute_anomaly_decision(fusion_features)
        >>> decision.verdict
        Verdict.PASS
        >>> decision.anomaly_score
        0.25
        >>> decision.reasons
        []
    """
    # Compute anomaly score
    anomaly_score = compute_anomaly_score(features)
    
    # Determine verdict
    verdict = determine_verdict(anomaly_score)
    
    # Generate user-facing reasons (generic, security-conscious)
    reasons = generate_anomaly_reasons(features, anomaly_score)
    
    # Track triggered rules (for internal logging/debugging)
    triggered_rules = get_triggered_rules(features)
    
    # Create decision object
    decision = AnomalyDecision(
        verdict=verdict,
        anomaly_score=anomaly_score,
        reasons=reasons,
        triggered_rules=triggered_rules
    )
    
    logger.info(
        f"Anomaly decision: verdict={verdict.value}, score={anomaly_score:.3f}, "
        f"triggered_rules={triggered_rules}"
    )
    
    return decision


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "compute_anomaly_score",
    "generate_anomaly_reasons",
    "determine_verdict",
    "compute_anomaly_decision",
]
