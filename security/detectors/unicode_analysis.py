"""
Unicode threat analysis module.

Detects various Unicode-based attacks including:
- Zero-width character encoding
- Bidirectional override attacks
- Homoglyph substitution
- Emoji cipher patterns
- Unicode normalization exploits
"""

import time
import asyncio
import unicodedata
from typing import List, Dict, Any
from collections import Counter

from ..models.security_schemas import (
    ThreatVector,
    UnicodeThreatReport,
    ThreatLevel,
    SecurityRecommendation,
)
from ..utils.pattern_matcher import PatternMatcher
from ..utils.cache_manager import SecurityAnalysisCache
from app.utils.logger import get_logger

logger = get_logger(__name__)


class UnicodeThreatAnalyzer:
    """
    Comprehensive Unicode threat analyzer.
    
    Detects various Unicode-based attacks that can bypass
    traditional text analysis and pose security risks.
    """
    
    def __init__(self, cache: SecurityAnalysisCache = None):
        """
        Initialize analyzer.
        
        Args:
            cache: Optional cache for analysis results
        """
        self.cache = cache
        self.pattern_matcher = PatternMatcher()
        
        # Thresholds
        self.zero_width_density_threshold = 0.01  # 1%
        self.homoglyph_count_threshold = 3
        self.bidi_unmatched_threshold = 1
    
    async def analyze_text(self, text: str, timeout: int = 10) -> UnicodeThreatReport:
        """
        Perform comprehensive Unicode threat analysis.
        
        Args:
            text: Input text to analyze
            timeout: Analysis timeout in seconds
            
        Returns:
            Comprehensive threat report
        """
        start_time = time.time()
        
        try:
            # Check cache
            if self.cache:
                cache_key = SecurityAnalysisCache.generate_content_hash(text)
                cached = self.cache.get(cache_key)
                if cached:
                    logger.debug("Unicode analysis cache hit")
                    return cached
            
            # Run analyses in parallel with timeout
            try:
                threat_vectors = await asyncio.wait_for(
                    asyncio.gather(
                        self._detect_zero_width_encoding(text),
                        self._analyze_bidirectional_override(text),
                        self._detect_homoglyph_attacks(text),
                        self._analyze_emoji_sequences(text),
                        self._check_unicode_normalization(text),
                        return_exceptions=True
                    ),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Unicode analysis timed out after {timeout}s")
                return self._create_timeout_result(time.time() - start_time)
            
            # Filter out exceptions
            valid_vectors = [v for v in threat_vectors if not isinstance(v, Exception)]
            
            # Calculate overall score
            scores = [tv.threat_score for tv in valid_vectors]
            overall_score = max(scores) if scores else 0.0
            
            # Determine threat level
            threat_level = self._determine_threat_level(overall_score)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(valid_vectors)
            
            analysis_time = (time.time() - start_time) * 1000
            
            result = UnicodeThreatReport(
                threat_vectors=valid_vectors,
                overall_threat_score=overall_score,
                threat_level=threat_level,
                recommendations=recommendations,
                analysis_time_ms=analysis_time
            )
            
            # Cache result
            if self.cache:
                self.cache.set(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Unicode analysis failed: {e}")
            return self._create_error_result(str(e), time.time() - start_time)
    
    async def _detect_zero_width_encoding(self, text: str) -> ThreatVector:
        """
        Detect hidden messages in zero-width characters.
        
        Args:
            text: Input text
            
        Returns:
            Threat vector for zero-width encoding
        """
        try:
            detection = self.pattern_matcher.detect_zero_width_chars(text)
            
            if not detection['detected']:
                return ThreatVector(
                    type="zero_width",
                    threat_score=0.0,
                    details="No zero-width characters detected",
                    pattern_analysis=detection
                )
            
            # Calculate threat score based on density and pattern
            density = detection['density']
            suspicious = detection.get('suspicious', False)
            
            # Analyze sequence patterns
            pattern_complexity = self._analyze_zwc_sequences(text, detection['positions'])
            
            # Higher density and complex patterns = higher threat
            threat_score = min(1.0, density * 10 + pattern_complexity * 0.5)
            if suspicious:
                threat_score = min(1.0, threat_score + 0.2)
            
            # Extract samples
            samples = []
            for pos in detection['positions'][:5]:  # First 5 samples
                context_start = max(0, pos - 10)
                context_end = min(len(text), pos + 10)
                samples.append(text[context_start:context_end])
            
            return ThreatVector(
                type="zero_width",
                threat_score=threat_score,
                details=f"Found {detection['count']} zero-width characters (density: {density:.2%})",
                pattern_analysis=detection,
                samples=samples
            )
            
        except Exception as e:
            logger.error(f"Zero-width detection failed: {e}")
            return ThreatVector(
                type="zero_width",
                threat_score=0.0,
                details=f"Analysis error: {str(e)}"
            )
    
    async def _analyze_bidirectional_override(self, text: str) -> ThreatVector:
        """
        Analyze bidirectional override impact.
        
        Args:
            text: Input text
            
        Returns:
            Threat vector for bidi attacks
        """
        try:
            detection = self.pattern_matcher.detect_bidi_chars(text)
            
            if not detection['detected']:
                return ThreatVector(
                    type="bidirectional_override",
                    threat_score=0.0,
                    details="No bidirectional override characters detected"
                )
            
            unmatched = detection.get('unmatched', 0)
            count = detection['count']
            
            # Unmatched bidi chars are highly suspicious
            if unmatched > self.bidi_unmatched_threshold:
                threat_score = 0.9
                details = f"Found {count} bidi characters with {unmatched} unmatched (likely attack)"
            elif count > 5:
                threat_score = 0.6
                details = f"Found {count} bidi characters (possible attack)"
            else:
                threat_score = 0.3
                details = f"Found {count} bidi characters (low risk)"
            
            return ThreatVector(
                type="bidirectional_override",
                threat_score=threat_score,
                details=details,
                pattern_analysis=detection
            )
            
        except Exception as e:
            logger.error(f"Bidi analysis failed: {e}")
            return ThreatVector(
                type="bidirectional_override",
                threat_score=0.0,
                details=f"Analysis error: {str(e)}"
            )
    
    async def _detect_homoglyph_attacks(self, text: str) -> ThreatVector:
        """
        Detect homoglyph substitution attacks.
        
        Args:
            text: Input text
            
        Returns:
            Threat vector for homoglyph attacks
        """
        try:
            detection = self.pattern_matcher.detect_homoglyphs(text)
            
            if not detection['detected']:
                return ThreatVector(
                    type="homoglyph",
                    threat_score=0.0,
                    details="No homoglyph substitutions detected"
                )
            
            count = detection['count']
            suspicious = detection.get('suspicious', False)
            
            # Calculate threat score
            if suspicious:
                threat_score = 0.8
            elif count > self.homoglyph_count_threshold:
                threat_score = 0.6
            else:
                threat_score = 0.3
            
            # Extract sample homoglyphs
            samples = []
            for h in detection['homoglyphs'][:5]:
                samples.append(f"{h['char']} (looks like '{h['looks_like']}', {h['unicode']})")
            
            return ThreatVector(
                type="homoglyph",
                threat_score=threat_score,
                details=f"Found {count} homoglyph substitutions",
                pattern_analysis=detection,
                samples=samples
            )
            
        except Exception as e:
            logger.error(f"Homoglyph detection failed: {e}")
            return ThreatVector(
                type="homoglyph",
                threat_score=0.0,
                details=f"Analysis error: {str(e)}"
            )
    
    async def _analyze_emoji_sequences(self, text: str) -> ThreatVector:
        """
        Analyze emoji sequences for encoding patterns.
        
        Args:
            text: Input text
            
        Returns:
            Threat vector for emoji cipher
        """
        try:
            # Extract emojis
            emojis = [char for char in text if self._is_emoji(char)]
            
            if not emojis:
                return ThreatVector(
                    type="emoji_cipher",
                    threat_score=0.0,
                    details="No emojis detected"
                )
            
            # Analyze patterns
            emoji_density = len(emojis) / len(text) if text else 0
            unique_emojis = len(set(emojis))
            repetition_score = len(emojis) / unique_emojis if unique_emojis > 0 else 1
            
            # High density with low repetition suggests encoding
            threat_score = 0.0
            if emoji_density > 0.1:  # More than 10% emojis
                threat_score += 0.4
            if unique_emojis > 20:  # Many unique emojis
                threat_score += 0.3
            if repetition_score < 2:  # Low repetition
                threat_score += 0.3
            
            details = f"Found {len(emojis)} emojis ({unique_emojis} unique, density: {emoji_density:.2%})"
            
            return ThreatVector(
                type="emoji_cipher",
                threat_score=min(threat_score, 1.0),
                details=details,
                pattern_analysis={
                    'total_emojis': len(emojis),
                    'unique_emojis': unique_emojis,
                    'density': emoji_density,
                    'repetition_score': repetition_score
                },
                samples=emojis[:10]
            )
            
        except Exception as e:
            logger.error(f"Emoji analysis failed: {e}")
            return ThreatVector(
                type="emoji_cipher",
                threat_score=0.0,
                details=f"Analysis error: {str(e)}"
            )
    
    async def _check_unicode_normalization(self, text: str) -> ThreatVector:
        """
        Check for Unicode normalization exploits.
        
        Args:
            text: Input text
            
        Returns:
            Threat vector for normalization issues
        """
        try:
            # Compare different normalization forms
            nfc = unicodedata.normalize('NFC', text)
            nfd = unicodedata.normalize('NFD', text)
            nfkc = unicodedata.normalize('NFKC', text)
            nfkd = unicodedata.normalize('NFKD', text)
            
            # Check if different forms produce different results
            forms_differ = not all([
                text == nfc,
                text == nfd,
                nfc == nfkc,
                nfd == nfkd
            ])
            
            if not forms_differ:
                return ThreatVector(
                    type="normalization",
                    threat_score=0.0,
                    details="No normalization issues detected"
                )
            
            # Significant differences suggest potential exploit
            len_diff = max([
                abs(len(text) - len(nfc)),
                abs(len(text) - len(nfkc)),
                abs(len(nfc) - len(nfkc))
            ])
            
            # Calculate threat score
            if len_diff > 10:
                threat_score = 0.7
                details = "Significant normalization differences detected (possible exploit)"
            elif len_diff > 5:
                threat_score = 0.5
                details = "Moderate normalization differences detected"
            else:
                threat_score = 0.3
                details = "Minor normalization differences detected"
            
            return ThreatVector(
                type="normalization",
                threat_score=threat_score,
                details=details,
                pattern_analysis={
                    'original_length': len(text),
                    'nfc_length': len(nfc),
                    'nfkc_length': len(nfkc),
                    'max_difference': len_diff
                }
            )
            
        except Exception as e:
            logger.error(f"Normalization check failed: {e}")
            return ThreatVector(
                type="normalization",
                threat_score=0.0,
                details=f"Analysis error: {str(e)}"
            )
    
    def _analyze_zwc_sequences(self, text: str, positions: List[int]) -> float:
        """
        Analyze zero-width character sequences for patterns.
        
        Args:
            text: Full text
            positions: Positions of zero-width chars
            
        Returns:
            Pattern complexity score (0-1)
        """
        if len(positions) < 2:
            return 0.0
        
        # Analyze spacing between zero-width chars
        spacings = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
        
        # Regular spacing suggests encoding
        spacing_variance = sum((s - sum(spacings)/len(spacings))**2 for s in spacings) / len(spacings)
        
        # Low variance = regular spacing = suspicious
        if spacing_variance < 10:
            return 0.8
        elif spacing_variance < 50:
            return 0.5
        else:
            return 0.2
    
    def _is_emoji(self, char: str) -> bool:
        """Check if character is an emoji."""
        code_point = ord(char)
        return (
            0x1F600 <= code_point <= 0x1F64F or  # Emoticons
            0x1F300 <= code_point <= 0x1F5FF or  # Miscellaneous Symbols
            0x1F680 <= code_point <= 0x1F6FF or  # Transport and Map
            0x2600 <= code_point <= 0x26FF or    # Miscellaneous symbols
            0x2700 <= code_point <= 0x27BF        # Dingbats
        )
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Determine threat level from score."""
        if score < 0.2:
            return ThreatLevel.NONE
        elif score < 0.4:
            return ThreatLevel.LOW
        elif score < 0.6:
            return ThreatLevel.MEDIUM
        elif score < 0.8:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL
    
    def _generate_recommendations(self, threat_vectors: List[ThreatVector]) -> List[SecurityRecommendation]:
        """Generate security recommendations based on detected threats."""
        recommendations = []
        
        for vector in threat_vectors:
            if vector.threat_score < 0.3:
                continue
            
            if vector.type == "zero_width":
                recommendations.append(SecurityRecommendation(
                    action="Strip zero-width characters from input",
                    priority="high",
                    reasoning="Zero-width characters can hide malicious content"
                ))
            elif vector.type == "bidirectional_override":
                recommendations.append(SecurityRecommendation(
                    action="Remove or neutralize bidirectional override characters",
                    priority="high",
                    reasoning="Bidi attacks can disguise malicious text direction"
                ))
            elif vector.type == "homoglyph":
                recommendations.append(SecurityRecommendation(
                    action="Convert to normalized ASCII or flag for review",
                    priority="medium",
                    reasoning="Homoglyphs can bypass text filters"
                ))
            elif vector.type == "emoji_cipher":
                recommendations.append(SecurityRecommendation(
                    action="Limit emoji density or flag for review",
                    priority="medium",
                    reasoning="High emoji density may indicate steganographic encoding"
                ))
            elif vector.type == "normalization":
                recommendations.append(SecurityRecommendation(
                    action="Apply NFKC normalization before processing",
                    priority="medium",
                    reasoning="Normalization exploits can bypass security checks"
                ))
        
        return recommendations
    
    def _create_timeout_result(self, elapsed_time: float) -> UnicodeThreatReport:
        """Create result for timeout case."""
        return UnicodeThreatReport(
            threat_vectors=[],
            overall_threat_score=0.5,
            threat_level=ThreatLevel.MEDIUM,
            recommendations=[
                SecurityRecommendation(
                    action="Retry analysis with higher timeout",
                    priority="low",
                    reasoning="Analysis timed out before completion"
                )
            ],
            analysis_time_ms=elapsed_time * 1000
        )
    
    def _create_error_result(self, error: str, elapsed_time: float) -> UnicodeThreatReport:
        """Create result for error case."""
        return UnicodeThreatReport(
            threat_vectors=[],
            overall_threat_score=0.0,
            threat_level=ThreatLevel.NONE,
            recommendations=[],
            analysis_time_ms=elapsed_time * 1000
        )
