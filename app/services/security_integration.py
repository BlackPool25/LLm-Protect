"""
Security integration service.

Integrates all security detectors and analyzers with the existing
input preparation pipeline.
"""

import time
import asyncio
from typing import Optional, Dict, Any
import hashlib

from security.detectors.steganography import SteganographyDetector
from security.detectors.unicode_analysis import UnicodeThreatAnalyzer
from security.analyzers.semantic_conflict import SemanticConflictDetector
from security.analyzers.behavioral import BehavioralAnalyzer, get_global_analyzer
from security.models.security_schemas import (
    SecurityReport,
    SecurityMetadata,
    SecurityAnomaly,
    ThreatLevel,
)
from security.utils.cache_manager import SecurityAnalysisCache, get_global_cache
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityIntegrationService:
    """
    Main security integration service.
    
    Coordinates all security detectors and analyzers to provide
    comprehensive threat assessment.
    """
    
    def __init__(self):
        """Initialize security service with all detectors."""
        # Initialize cache if enabled
        self.cache = None
        if settings.ENABLE_SECURITY_CACHE:
            self.cache = SecurityAnalysisCache(
                max_size=settings.SECURITY_CACHE_MAX_SIZE,
                ttl=settings.SECURITY_CACHE_TTL
            )
        
        # Initialize detectors
        self.steg_detector = SteganographyDetector(cache=self.cache) if settings.ENABLE_STEGANOGRAPHY_DETECTION else None
        self.unicode_analyzer = UnicodeThreatAnalyzer(cache=self.cache) if settings.ENABLE_ADVANCED_UNICODE_ANALYSIS else None
        self.conflict_detector = SemanticConflictDetector(cache=self.cache) if settings.ENABLE_SEMANTIC_CONFLICT_DETECTION else None
        self.behavioral_analyzer = get_global_analyzer() if settings.ENABLE_BEHAVIORAL_ANALYSIS else None
        
        logger.info("Security Integration Service initialized")
        logger.info(f"  - Steganography detection: {settings.ENABLE_STEGANOGRAPHY_DETECTION}")
        logger.info(f"  - Unicode analysis: {settings.ENABLE_ADVANCED_UNICODE_ANALYSIS}")
        logger.info(f"  - Semantic conflict detection: {settings.ENABLE_SEMANTIC_CONFLICT_DETECTION}")
        logger.info(f"  - Behavioral analysis: {settings.ENABLE_BEHAVIORAL_ANALYSIS}")
        logger.info(f"  - Cache enabled: {settings.ENABLE_SECURITY_CACHE}")
    
    async def analyze_text(
        self,
        text: str,
        client_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityReport:
        """
        Perform comprehensive security analysis on text input.
        
        Args:
            text: Input text to analyze
            client_id: Optional client identifier for behavioral analysis
            metadata: Optional metadata for conflict detection
            
        Returns:
            Comprehensive security report
        """
        start_time = time.time()
        analysis_tasks = []
        analysis_enabled = {}
        
        # Unicode threat analysis
        if self.unicode_analyzer:
            analysis_tasks.append(('unicode', self.unicode_analyzer.analyze_text(text)))
            analysis_enabled['unicode_analysis'] = True
        
        # Semantic conflict detection (text-only mode)
        if self.conflict_detector:
            analysis_tasks.append(('conflict', self.conflict_detector.check_consistency(text, metadata)))
            analysis_enabled['conflict_detection'] = True
        
        # Behavioral analysis
        behavioral_profile = None
        if self.behavioral_analyzer and client_id:
            request_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
            behavioral_profile = await self.behavioral_analyzer.analyze(client_id, text, request_hash)
            analysis_enabled['behavioral_analysis'] = True
        
        # Execute analyses with timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*[task for _, task in analysis_tasks], return_exceptions=True),
                timeout=settings.MAX_SECURITY_ANALYSIS_TIME_MS / 1000
            )
        except asyncio.TimeoutError:
            logger.warning("Security analysis timed out")
            return self._create_timeout_report(time.time() - start_time, analysis_enabled)
        
        # Process results
        unicode_report = None
        conflict_analysis = None
        
        for i, (analysis_type, _) in enumerate(analysis_tasks):
            if i < len(results) and not isinstance(results[i], Exception):
                if analysis_type == 'unicode':
                    unicode_report = results[i]
                elif analysis_type == 'conflict':
                    conflict_analysis = results[i]
        
        # Aggregate results into security report
        report = self._aggregate_report(
            unicode_report=unicode_report,
            conflict_analysis=conflict_analysis,
            behavioral_profile=behavioral_profile,
            analysis_time=time.time() - start_time,
            analysis_enabled=analysis_enabled
        )
        
        return report
    
    async def analyze_media(
        self,
        media_data: bytes,
        text: Optional[str] = None,
        client_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityReport:
        """
        Perform comprehensive security analysis on media input.
        
        Args:
            media_data: Media data (image, etc.)
            text: Optional associated text
            client_id: Optional client identifier for behavioral analysis
            metadata: Optional metadata for conflict detection
            
        Returns:
            Comprehensive security report
        """
        start_time = time.time()
        analysis_tasks = []
        analysis_enabled = {}
        
        # Steganography detection
        if self.steg_detector:
            analysis_tasks.append(('stego', self.steg_detector.analyze(media_data)))
            analysis_enabled['steganography_detection'] = True
        
        # Unicode analysis on associated text
        unicode_report = None
        if self.unicode_analyzer and text:
            unicode_report = await self.unicode_analyzer.analyze_text(text)
            analysis_enabled['unicode_analysis'] = True
        
        # Semantic conflict detection (multimodal)
        if self.conflict_detector:
            analysis_tasks.append(('conflict', self.conflict_detector.check_consistency(media_data, metadata)))
            analysis_enabled['conflict_detection'] = True
        
        # Behavioral analysis
        behavioral_profile = None
        if self.behavioral_analyzer and client_id:
            request_hash = hashlib.sha256(media_data).hexdigest()[:16]
            behavioral_profile = await self.behavioral_analyzer.analyze(client_id, media_data, request_hash)
            analysis_enabled['behavioral_analysis'] = True
        
        # Execute analyses with timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*[task for _, task in analysis_tasks], return_exceptions=True),
                timeout=settings.MAX_SECURITY_ANALYSIS_TIME_MS / 1000
            )
        except asyncio.TimeoutError:
            logger.warning("Media security analysis timed out")
            return self._create_timeout_report(time.time() - start_time, analysis_enabled)
        
        # Process results
        stego_analysis = None
        conflict_analysis = None
        
        for i, (analysis_type, _) in enumerate(analysis_tasks):
            if i < len(results) and not isinstance(results[i], Exception):
                if analysis_type == 'stego':
                    stego_analysis = results[i]
                elif analysis_type == 'conflict':
                    conflict_analysis = results[i]
        
        # Aggregate results
        report = self._aggregate_report(
            stego_analysis=stego_analysis,
            unicode_report=unicode_report,
            conflict_analysis=conflict_analysis,
            behavioral_profile=behavioral_profile,
            analysis_time=time.time() - start_time,
            analysis_enabled=analysis_enabled
        )
        
        return report
    
    def _aggregate_report(
        self,
        stego_analysis=None,
        unicode_report=None,
        conflict_analysis=None,
        behavioral_profile=None,
        analysis_time: float = 0.0,
        analysis_enabled: Dict[str, bool] = None
    ) -> SecurityReport:
        """
        Aggregate all analysis results into a unified security report.
        
        Args:
            stego_analysis: Steganography analysis result
            unicode_report: Unicode threat report
            conflict_analysis: Conflict analysis result
            behavioral_profile: Behavioral profile
            analysis_time: Total analysis time in seconds
            analysis_enabled: Which analyses were enabled
            
        Returns:
            Unified security report
        """
        # Extract individual scores
        stego_score = stego_analysis.overall_stego_score if stego_analysis else 0.0
        unicode_score = unicode_report.overall_threat_score if unicode_report else 0.0
        conflict_score = conflict_analysis.conflict_score if conflict_analysis else 0.0
        behavioral_score = behavioral_profile.anomaly_score if behavioral_profile else 0.0
        
        # Calculate overall threat score (weighted average)
        weights = []
        scores = []
        
        if stego_score > 0:
            scores.append(stego_score)
            weights.append(0.3)
        if unicode_score > 0:
            scores.append(unicode_score)
            weights.append(0.3)
        if conflict_score > 0:
            scores.append(conflict_score)
            weights.append(0.25)
        if behavioral_score > 0:
            scores.append(behavioral_score)
            weights.append(0.15)
        
        if scores:
            total_weight = sum(weights)
            overall_score = sum(s * w for s, w in zip(scores, weights)) / total_weight
        else:
            overall_score = 0.0
        
        # Determine overall threat level
        overall_threat_level = self._determine_threat_level(overall_score)
        
        # Collect all anomalies
        detected_anomalies = []
        
        if unicode_report and unicode_report.threat_vectors:
            for vector in unicode_report.threat_vectors:
                if vector.threat_score > 0.3:
                    detected_anomalies.append(SecurityAnomaly(
                        type=f"unicode_{vector.type}",
                        severity=self._determine_threat_level(vector.threat_score),
                        description=vector.details,
                        confidence=vector.threat_score,
                        metadata={'samples': vector.samples[:3] if vector.samples else []}
                    ))
        
        if stego_analysis and stego_analysis.overall_stego_score > 0.3:
            detected_anomalies.append(SecurityAnomaly(
                type="steganography",
                severity=stego_analysis.threat_level,
                description=f"Potential steganography detected (score: {stego_analysis.overall_stego_score:.2f})",
                confidence=stego_analysis.overall_stego_score,
                metadata={}
            ))
        
        if conflict_analysis and conflict_analysis.detected_conflicts:
            for conflict in conflict_analysis.detected_conflicts:
                detected_anomalies.append(SecurityAnomaly(
                    type="semantic_conflict",
                    severity=conflict_analysis.threat_level,
                    description=conflict,
                    confidence=conflict_analysis.confidence,
                    metadata=conflict_analysis.similarity_metrics
                ))
        
        # Collect recommendations
        recommendations = []
        if unicode_report:
            recommendations.extend(unicode_report.recommendations)
        
        return SecurityReport(
            steganography_score=stego_score,
            unicode_threat_score=unicode_score,
            semantic_conflict_score=conflict_score,
            behavioral_anomaly_score=behavioral_score,
            overall_threat_score=overall_score,
            overall_threat_level=overall_threat_level,
            detected_anomalies=detected_anomalies,
            recommendations=recommendations,
            analysis_time_ms=analysis_time * 1000,
            analysis_enabled=analysis_enabled or {},
            stego_analysis=stego_analysis,
            unicode_analysis=unicode_report,
            conflict_analysis=conflict_analysis,
            behavioral_profile=behavioral_profile
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
    
    def _create_timeout_report(self, elapsed_time: float, analysis_enabled: Dict[str, bool]) -> SecurityReport:
        """Create security report for timeout case."""
        return SecurityReport(
            steganography_score=0.0,
            unicode_threat_score=0.0,
            semantic_conflict_score=0.0,
            behavioral_anomaly_score=0.0,
            overall_threat_score=0.5,
            overall_threat_level=ThreatLevel.MEDIUM,
            detected_anomalies=[
                SecurityAnomaly(
                    type="timeout",
                    severity=ThreatLevel.MEDIUM,
                    description="Security analysis timed out",
                    confidence=1.0,
                    metadata={}
                )
            ],
            recommendations=[],
            analysis_time_ms=elapsed_time * 1000,
            analysis_enabled=analysis_enabled
        )
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if self.cache:
            return self.cache.get_stats()
        return {}


# Global service instance
_security_service: Optional[SecurityIntegrationService] = None


def get_security_service() -> SecurityIntegrationService:
    """Get or create global security service instance."""
    global _security_service
    if _security_service is None:
        _security_service = SecurityIntegrationService()
    return _security_service
