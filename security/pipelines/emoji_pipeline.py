"""
Emoji and text processing pipeline for the Security Guard System.

This module handles all text and emoji-based threat detection including:
- Emoji extraction and normalization
- Emoji risk mapping and scoring
- Emoji pattern analysis (repetition, cipher detection)
- Unicode threat detection
- Feature pack assembly
"""

import re
import json
import unicodedata
from typing import List, Tuple, Dict, Set
from pathlib import Path

from security.core.types import (
    EmojiExtractionResult,
    EmojiPatternFeatures,
    UnicodeThreatFeatures,
    EmojiFeaturePack,
)
from security.detectors.unicode_analysis import UnicodeThreatAnalyzer
from config.security_config import (
    EMOJI_RISK_MAP_PATH,
    FALLBACK_EMOJI_RISK_SCORES,
    MIN_EMOJI_REPETITION_COUNT,
    EMOJI_CIPHER_MIN_LENGTH,
    ZERO_WIDTH_CHARS,
    BIDI_OVERRIDE_CHARS,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# Emoji Risk Map Loader
# ============================================================================

class EmojiRiskMapper:
    """
    Loads and manages emoji risk mappings from JSON configuration.
    Falls back to hardcoded mappings if JSON is unavailable.
    """
    
    def __init__(self):
        self.risk_map: Dict[str, Dict[str, any]] = {}
        self.emoji_to_category: Dict[str, Tuple[str, float]] = {}
        self._load_risk_map()
    
    def _load_risk_map(self):
        """Load emoji risk map from JSON file with fallback."""
        try:
            # Try to load from JSON
            json_path = Path(EMOJI_RISK_MAP_PATH)
            if json_path.exists():
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.risk_map = data.get('risk_categories', {})
                    logger.info(f"Loaded emoji risk map from {EMOJI_RISK_MAP_PATH}")
            else:
                logger.warning(f"Emoji risk map not found at {EMOJI_RISK_MAP_PATH}, using fallback")
                self._use_fallback()
                
            # Build reverse mapping: emoji -> (category, score)
            for category, info in self.risk_map.items():
                score = info.get('score', FALLBACK_EMOJI_RISK_SCORES.get(category, 0.5))
                emojis = info.get('emojis', [])
                for emoji in emojis:
                    self.emoji_to_category[emoji] = (category, score)
                    
        except Exception as e:
            logger.error(f"Failed to load emoji risk map: {e}")
            self._use_fallback()
    
    def _use_fallback(self):
        """Use hardcoded fallback mappings."""
        # Minimal fallback - just scores
        self.risk_map = {
            category: {"score": score, "emojis": []}
            for category, score in FALLBACK_EMOJI_RISK_SCORES.items()
        }
    
    def get_risk(self, emoji: str) -> Tuple[str, float]:
        """
        Get risk category and score for an emoji.
        
        Args:
            emoji: Emoji character or sequence
            
        Returns:
            Tuple of (category, score). Returns ("unknown", 0.3) if not found.
        """
        return self.emoji_to_category.get(emoji, ("unknown", 0.3))


# Global emoji risk mapper instance
_emoji_risk_mapper = EmojiRiskMapper()


# ============================================================================
# Emoji Extraction
# ============================================================================

def extract_emojis_and_normalize(text: str) -> EmojiExtractionResult:
    """
    Extract emojis from text and create normalized versions.
    
    Args:
        text: Input text
        
    Returns:
        EmojiExtractionResult with extracted emojis and normalized text
        
    Example:
        >>> result = extract_emojis_and_normalize("Hello 😀 World 🌍!")
        >>> result.emojis
        ['😀', '🌍']
        >>> result.emoji_count
        2
    """
    # Emoji regex pattern (Unicode emoji ranges)
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags (iOS)
        "\U00002702-\U000027B0"  # dingbats
        "\U000024C2-\U0001F251"  # enclosed characters
        "\U0001F900-\U0001F9FF"  # supplemental symbols
        "\U0001FA00-\U0001FA6F"  # extended symbols
        "]+",
        flags=re.UNICODE
    )
    
    # Extract all emojis
    emojis = emoji_pattern.findall(text)
    
    # Create normalized text (emojis replaced with placeholder)
    normalized_text = emoji_pattern.sub(' [EMOJI] ', text)
    normalized_text = re.sub(r'\s+', ' ', normalized_text).strip()
    
    # Create stripped text (emojis completely removed)
    stripped_text = emoji_pattern.sub('', text)
    stripped_text = re.sub(r'\s+', ' ', stripped_text).strip()
    
    return EmojiExtractionResult(
        emojis=emojis,
        normalized_text=normalized_text,
        stripped_text=stripped_text,
        emoji_count=len(emojis)
    )


# ============================================================================
# Emoji Risk Mapping
# ============================================================================

def map_emojis_to_risk(emojis: List[str]) -> Tuple[float, List[str]]:
    """
    Map emojis to risk categories and compute overall risk score.
    
    Args:
        emojis: List of emoji characters
        
    Returns:
        Tuple of (overall_risk_score, triggered_categories)
        
    Example:
        >>> score, categories = map_emojis_to_risk(['🔫', '💣', '😀'])
        >>> score
        0.9  # High risk due to weapons
        >>> categories
        ['weapons', 'violent', 'neutral']
    """
    if not emojis:
        return 0.0, []
    
    risk_scores = []
    categories_set: Set[str] = set()
    
    for emoji in emojis:
        category, score = _emoji_risk_mapper.get_risk(emoji)
        risk_scores.append(score)
        categories_set.add(category)
    
    # Overall risk score is the maximum (most risky emoji determines overall risk)
    overall_risk = max(risk_scores) if risk_scores else 0.0
    
    # Return sorted list of unique categories
    categories = sorted(list(categories_set))
    
    logger.debug(f"Emoji risk: {overall_risk:.3f}, categories: {categories}")
    return overall_risk, categories


# ============================================================================
# Emoji Pattern Analysis
# ============================================================================

def analyze_emoji_patterns(emojis: List[str], text: str) -> EmojiPatternFeatures:
    """
    Analyze emoji sequences for suspicious patterns.
    
    Detects:
    - Repetitive emoji spam
    - Cipher-like emoji sequences
    - Mixed script + emoji patterns
    
    Args:
        emojis: List of extracted emojis
        text: Original text
        
    Returns:
        EmojiPatternFeatures with analysis results
    """
    if not emojis:
        return EmojiPatternFeatures(
            repetition_score=0.0,
            cipher_like=False,
            mixed_script_with_emoji=False,
            suspicious_sequences=[],
            pattern_complexity=0.0
        )
    
    # Detect repetition
    repetition_score = _detect_emoji_repetition(emojis)
    
    # Detect cipher-like patterns
    cipher_like = _detect_emoji_cipher(emojis)
    
    # Detect mixed script patterns
    mixed_script = _detect_mixed_script_emoji(text, emojis)
    
    # Find suspicious sequences
    suspicious_seqs = _find_suspicious_sequences(emojis)
    
    # Compute overall pattern complexity
    pattern_complexity = min(1.0, (
        repetition_score * 0.4 +
        (1.0 if cipher_like else 0.0) * 0.3 +
        (1.0 if mixed_script else 0.0) * 0.3
    ))
    
    return EmojiPatternFeatures(
        repetition_score=repetition_score,
        cipher_like=cipher_like,
        mixed_script_with_emoji=mixed_script,
        suspicious_sequences=suspicious_seqs,
        pattern_complexity=pattern_complexity
    )


def _detect_emoji_repetition(emojis: List[str]) -> float:
    """
    Detect repetitive emoji patterns (spam indicator).
    
    Returns score 0-1 based on repetition frequency.
    """
    if len(emojis) < MIN_EMOJI_REPETITION_COUNT:
        return 0.0
    
    # Count emoji frequencies
    emoji_counts = {}
    for emoji in emojis:
        emoji_counts[emoji] = emoji_counts.get(emoji, 0) + 1
    
    # Find max repetition
    max_count = max(emoji_counts.values())
    
    # Score based on repetition ratio
    if max_count >= MIN_EMOJI_REPETITION_COUNT:
        repetition_ratio = max_count / len(emojis)
        return min(1.0, repetition_ratio * 2)  # Scale up for scoring
    
    return 0.0


def _detect_emoji_cipher(emojis: List[str]) -> bool:
    """
    Detect if emoji sequence looks like a cipher/encoding.
    
    Heuristic: long sequence of unique emojis (not repetitive).
    """
    if len(emojis) < EMOJI_CIPHER_MIN_LENGTH:
        return False
    
    # Cipher-like if mostly unique emojis in sequence
    unique_ratio = len(set(emojis)) / len(emojis)
    return unique_ratio > 0.7 and len(emojis) >= EMOJI_CIPHER_MIN_LENGTH


def _detect_mixed_script_emoji(text: str, emojis: List[str]) -> bool:
    """
    Detect mixed script (e.g., Latin + Cyrillic) combined with emojis.
    
    This can indicate obfuscation attempts.
    """
    if not emojis:
        return False
    
    # Remove emojis from text
    text_no_emoji = text
    for emoji in emojis:
        text_no_emoji = text_no_emoji.replace(emoji, '')
    
    # Detect scripts in remaining text
    scripts = set()
    for char in text_no_emoji:
        if char.isalpha():
            try:
                script = unicodedata.name(char).split()[0]
                scripts.add(script)
            except:
                pass
    
    # Mixed script if more than one script detected
    return len(scripts) > 1


def _find_suspicious_sequences(emojis: List[str]) -> List[str]:
    """
    Find suspicious emoji sequences (e.g., all weapons, all violent).
    
    Returns list of suspicious sequence descriptions.
    """
    suspicious = []
    
    # Check for sequences of high-risk emojis
    high_risk_count = 0
    for emoji in emojis:
        category, score = _emoji_risk_mapper.get_risk(emoji)
        if score >= 0.7:  # High risk threshold
            high_risk_count += 1
    
    if high_risk_count >= 3:
        suspicious.append(f"{high_risk_count} high-risk emojis in sequence")
    
    return suspicious


# ============================================================================
# Unicode Threat Detection
# ============================================================================

async def detect_unicode_threats(text: str) -> UnicodeThreatFeatures:
    """
    Detect Unicode-based threats using existing analyzer.
    
    Wraps the existing UnicodeThreatAnalyzer to output standardized features.
    
    Args:
        text: Input text
        
    Returns:
        UnicodeThreatFeatures with detection results
    """
    try:
        analyzer = UnicodeThreatAnalyzer()
        result = await analyzer.analyze_text(text)
        
        # Extract features from analyzer result
        has_zero_width = any(
            tv.type == "zero_width_encoding" or tv.type == "zero_width" for tv in result.threat_vectors
        )
        has_bidi = any(
            tv.type == "bidi_override" or tv.type == "bidirectional_override" for tv in result.threat_vectors
        )
        has_homoglyphs = any(
            tv.type == "homoglyph_attack" or tv.type == "homoglyph" for tv in result.threat_vectors
        )
        
        # Count specific threats
        zero_width_count = sum(1 for char in text if char in ZERO_WIDTH_CHARS)
        bidi_count = sum(1 for char in text if char in BIDI_OVERRIDE_CHARS)
        
        # Estimate homoglyph count (simplified)
        homoglyph_count = 0
        for tv in result.threat_vectors:
            if tv.type in ["homoglyph_attack", "homoglyph"]:
                homoglyph_count += 1
        
        # Collect threat flags
        threat_flags = [tv.type for tv in result.threat_vectors]
        
        return UnicodeThreatFeatures(
            has_zero_width=has_zero_width,
            has_bidi_override=has_bidi,
            has_homoglyphs=has_homoglyphs,
            threat_flags=threat_flags,
            zero_width_count=zero_width_count,
            bidi_override_count=bidi_count,
            homoglyph_count=homoglyph_count,
            overall_unicode_threat_score=result.overall_threat_score
        )
        
    except Exception as e:
        logger.error(f"Unicode threat detection failed: {e}")
        # Return safe default on error
        return UnicodeThreatFeatures(
            has_zero_width=False,
            has_bidi_override=False,
            has_homoglyphs=False,
            threat_flags=[],
            zero_width_count=0,
            bidi_override_count=0,
            homoglyph_count=0,
            overall_unicode_threat_score=0.0
        )


# ============================================================================
# Main Pipeline Function
# ============================================================================

async def build_emoji_feature_pack(text: str) -> EmojiFeaturePack:
    """
    Build complete emoji/text feature pack.
    
    Orchestrates all emoji/text pipeline steps:
    1. Extract emojis and normalize text
    2. Map emojis to risk categories
    3. Analyze emoji patterns
    4. Detect Unicode threats
    5. Assemble feature pack
    
    Args:
        text: Input text
        
    Returns:
        EmojiFeaturePack with all features
    """
    # Step 1: Extract emojis
    extraction_result = extract_emojis_and_normalize(text)
    
    # Step 2: Map to risk categories
    emoji_risk_score, emoji_categories = map_emojis_to_risk(extraction_result.emojis)
    
    # Step 3: Analyze patterns
    pattern_features = analyze_emoji_patterns(extraction_result.emojis, text)
    
    # Step 4: Detect Unicode threats (async)
    unicode_threats = await detect_unicode_threats(text)
    
    # Assemble feature pack
    feature_pack = EmojiFeaturePack(
        emoji_risk_score=emoji_risk_score,
        emoji_categories=emoji_categories,
        emoji_sequence=extraction_result.emojis,
        pattern_features=pattern_features,
        unicode_threats=unicode_threats
    )
    
    logger.info(
        f"Emoji feature pack built: risk_score={emoji_risk_score:.3f}, "
        f"categories={emoji_categories}, unicode_threat={unicode_threats.overall_unicode_threat_score:.3f}"
    )
    return feature_pack


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "extract_emojis_and_normalize",
    "map_emojis_to_risk",
    "analyze_emoji_patterns",
    "detect_unicode_threats",
    "build_emoji_feature_pack",
]
