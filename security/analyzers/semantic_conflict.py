"""
Semantic conflict detection module.

Detects inconsistencies and conflicts between:
- Image content and text
- Metadata and actual content
- Multiple data modalities
"""

import time
import asyncio
from typing import Union, Dict, Any, Optional
import numpy as np

from ..models.security_schemas import (
    ConflictAnalysis,
    ThreatLevel,
)
from ..utils.cache_manager import SecurityAnalysisCache
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SemanticConflictDetector:
    """
    Detector for semantic conflicts across modalities.
    
    Analyzes consistency between different data sources
    to detect potential manipulation or attacks.
    """
    
    def __init__(self, cache: Optional[SecurityAnalysisCache] = None):
        """
        Initialize detector.
        
        Args:
            cache: Optional cache for analysis results
        """
        self.cache = cache
        self.similarity_threshold = 0.7
    
    async def check_consistency(
        self,
        input_data: Union[str, bytes],
        metadata: Optional[Dict[str, Any]] = None,
        timeout: int = 30
    ) -> ConflictAnalysis:
        """
        Check for semantic conflicts.
        
        Args:
            input_data: Input data (text or bytes)
            metadata: Optional metadata to check against
            timeout: Analysis timeout in seconds
            
        Returns:
            Conflict analysis result
        """
        start_time = time.time()
        
        try:
            if isinstance(input_data, str):
                return await self._analyze_text_consistency(input_data, metadata, timeout)
            else:
                return await self._analyze_multimodal_consistency(input_data, metadata, timeout)
                
        except asyncio.TimeoutError:
            logger.warning(f"Semantic conflict analysis timed out after {timeout}s")
            return self._create_timeout_result(time.time() - start_time)
        except Exception as e:
            logger.error(f"Semantic conflict analysis failed: {e}")
            return self._create_error_result(str(e), time.time() - start_time)
    
    async def _analyze_text_consistency(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]],
        timeout: int
    ) -> ConflictAnalysis:
        """
        Analyze consistency within text data.
        
        Args:
            text: Input text
            metadata: Optional metadata
            timeout: Timeout in seconds
            
        Returns:
            Conflict analysis
        """
        try:
            conflicts = []
            similarity_metrics = {}
            
            # Check for internal contradictions
            contradiction_score = await self._detect_contradictions(text)
            similarity_metrics['internal_consistency'] = 1.0 - contradiction_score
            
            if contradiction_score > 0.5:
                conflicts.append("Text contains potential contradictions")
            
            # Check metadata consistency if provided
            if metadata:
                metadata_score = await self._check_metadata_consistency(text, metadata)
                similarity_metrics['metadata_consistency'] = metadata_score
                
                if metadata_score < self.similarity_threshold:
                    conflicts.append("Text-metadata inconsistency detected")
            
            # Overall conflict score
            conflict_score = max(contradiction_score, 1.0 - similarity_metrics.get('metadata_consistency', 1.0))
            
            # Confidence based on available data
            confidence = 0.7 if metadata else 0.5
            
            threat_level = self._determine_threat_level(conflict_score)
            
            return ConflictAnalysis(
                conflict_score=conflict_score,
                detected_conflicts=conflicts,
                similarity_metrics=similarity_metrics,
                confidence=confidence,
                threat_level=threat_level
            )
            
        except Exception as e:
            logger.error(f"Text consistency analysis failed: {e}")
            return ConflictAnalysis(
                conflict_score=0.0,
                detected_conflicts=[],
                similarity_metrics={},
                confidence=0.0,
                threat_level=ThreatLevel.NONE,
                error=str(e)
            )
    
    async def _analyze_multimodal_consistency(
        self,
        media_data: bytes,
        metadata: Optional[Dict[str, Any]],
        timeout: int
    ) -> ConflictAnalysis:
        """
        Analyze consistency between different data modalities.
        
        Args:
            media_data: Media data (image, etc.)
            metadata: Optional metadata
            timeout: Timeout in seconds
            
        Returns:
            Conflict analysis
        """
        try:
            conflicts = []
            similarity_metrics = {}
            
            # For now, implement basic checks
            # Future: Add OCR, image classification, etc.
            
            # Check file header vs claimed type
            if metadata and 'format' in metadata:
                header_check = self._verify_file_header(media_data, metadata['format'])
                similarity_metrics['header_format_match'] = 1.0 if header_check else 0.0
                
                if not header_check:
                    conflicts.append("File header doesn't match claimed format")
            
            # Check metadata consistency
            if metadata:
                metadata_score = self._analyze_metadata_anomalies(metadata)
                similarity_metrics['metadata_validity'] = metadata_score
                
                if metadata_score < 0.7:
                    conflicts.append("Metadata contains anomalies")
            
            # Calculate overall conflict score
            if similarity_metrics:
                conflict_score = 1.0 - (sum(similarity_metrics.values()) / len(similarity_metrics))
            else:
                conflict_score = 0.0
            
            confidence = 0.6 if metadata else 0.3
            threat_level = self._determine_threat_level(conflict_score)
            
            return ConflictAnalysis(
                conflict_score=conflict_score,
                detected_conflicts=conflicts,
                similarity_metrics=similarity_metrics,
                confidence=confidence,
                threat_level=threat_level
            )
            
        except Exception as e:
            logger.error(f"Multimodal consistency analysis failed: {e}")
            return ConflictAnalysis(
                conflict_score=0.0,
                detected_conflicts=[],
                similarity_metrics={},
                confidence=0.0,
                threat_level=ThreatLevel.NONE,
                error=str(e)
            )
    
    async def _detect_contradictions(self, text: str) -> float:
        """
        Detect internal contradictions in text.
        
        This is a simplified implementation. Production version would use
        NLP models for semantic understanding.
        
        Args:
            text: Input text
            
        Returns:
            Contradiction score (0-1)
        """
        # Look for contradiction keywords
        negation_words = ['not', 'no', 'never', 'none', 'neither', 'nor', "don't", "doesn't", "didn't"]
        contradiction_words = ['but', 'however', 'although', 'despite', 'nevertheless', 'yet', 'except']
        
        text_lower = text.lower()
        
        negation_count = sum(1 for word in negation_words if word in text_lower.split())
        contradiction_count = sum(1 for word in contradiction_words if word in text_lower.split())
        
        # Simple heuristic: high frequency of contradictions/negations
        word_count = len(text.split())
        if word_count == 0:
            return 0.0
        
        negation_ratio = negation_count / word_count
        contradiction_ratio = contradiction_count / word_count
        
        # Combined score
        score = min(1.0, (negation_ratio * 5 + contradiction_ratio * 3))
        
        return score
    
    async def _check_metadata_consistency(self, text: str, metadata: Dict[str, Any]) -> float:
        """
        Check consistency between text and metadata.
        
        Args:
            text: Input text
            metadata: Metadata to check
            
        Returns:
            Consistency score (0-1)
        """
        # Simple keyword matching approach
        # Production version would use embeddings
        
        consistency_score = 1.0
        
        # Check if metadata fields make sense
        if 'title' in metadata:
            title_words = set(str(metadata['title']).lower().split())
            text_words = set(text.lower().split())
            
            # Calculate overlap
            if title_words:
                overlap = len(title_words & text_words) / len(title_words)
                consistency_score *= (0.5 + overlap * 0.5)
        
        if 'description' in metadata:
            desc_words = set(str(metadata['description']).lower().split())
            text_words = set(text.lower().split())
            
            if desc_words:
                overlap = len(desc_words & text_words) / len(desc_words)
                consistency_score *= (0.5 + overlap * 0.5)
        
        return consistency_score
    
    def _verify_file_header(self, data: bytes, claimed_format: str) -> bool:
        """
        Verify file header matches claimed format.
        
        Args:
            data: File data
            claimed_format: Claimed file format
            
        Returns:
            True if header matches
        """
        if len(data) < 4:
            return False
        
        # Common file signatures
        signatures = {
            'png': b'\x89PNG',
            'jpg': b'\xFF\xD8\xFF',
            'jpeg': b'\xFF\xD8\xFF',
            'gif': b'GIF',
            'pdf': b'%PDF',
            'zip': b'PK\x03\x04',
        }
        
        claimed_lower = claimed_format.lower().replace('.', '')
        
        if claimed_lower in signatures:
            expected_sig = signatures[claimed_lower]
            return data[:len(expected_sig)] == expected_sig
        
        # Unknown format, assume valid
        return True
    
    def _analyze_metadata_anomalies(self, metadata: Dict[str, Any]) -> float:
        """
        Analyze metadata for anomalies.
        
        Args:
            metadata: Metadata dictionary
            
        Returns:
            Validity score (0-1)
        """
        score = 1.0
        
        # Check for suspicious patterns
        if 'creation_date' in metadata and 'modification_date' in metadata:
            # Modification before creation is impossible
            try:
                if metadata['modification_date'] < metadata['creation_date']:
                    score *= 0.5
            except:
                pass
        
        # Check for unrealistic dimensions
        if 'width' in metadata and 'height' in metadata:
            try:
                width = int(metadata['width'])
                height = int(metadata['height'])
                
                # Unrealistically large dimensions
                if width > 100000 or height > 100000:
                    score *= 0.7
                
                # Unrealistically small
                if width < 1 or height < 1:
                    score *= 0.3
            except:
                pass
        
        return score
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Determine threat level from conflict score."""
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
    
    def _create_timeout_result(self, elapsed_time: float) -> ConflictAnalysis:
        """Create result for timeout case."""
        return ConflictAnalysis(
            conflict_score=0.5,
            detected_conflicts=["Analysis timed out"],
            similarity_metrics={},
            confidence=0.0,
            threat_level=ThreatLevel.MEDIUM,
            error="Analysis timeout"
        )
    
    def _create_error_result(self, error: str, elapsed_time: float) -> ConflictAnalysis:
        """Create result for error case."""
        return ConflictAnalysis(
            conflict_score=0.0,
            detected_conflicts=[],
            similarity_metrics={},
            confidence=0.0,
            threat_level=ThreatLevel.NONE,
            error=error
        )
