"""
Steganography detection module.

Implements lightweight CPU-friendly steganography detection using:
- LSB (Least Significant Bit) analysis
- Frequency domain analysis
- Noise pattern analysis
- Color channel correlation checks
"""

import io
import time
import asyncio
from typing import Optional, Dict, Any
import numpy as np
from PIL import Image

from ..models.security_schemas import (
    StegoAnalysis,
    LSBAnalysis,
    ThreatLevel,
)
from ..utils.entropy_calculator import (
    calculate_entropy,
    calculate_chi_square,
    calculate_lsb_entropy,
    analyze_bit_plane_complexity,
    calculate_correlation_coefficient,
)
from ..utils.cache_manager import SecurityAnalysisCache
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SteganographyDetector:
    """
    Lightweight steganography detector for images.
    
    Uses statistical analysis to detect hidden data without
    requiring GPU or deep learning models.
    """
    
    def __init__(self, cache: Optional[SecurityAnalysisCache] = None):
        """
        Initialize detector.
        
        Args:
            cache: Optional cache for analysis results
        """
        self.cache = cache
        
        # Thresholds for detection
        self.lsb_entropy_threshold = 0.95  # High entropy in LSB is suspicious
        self.chi_square_threshold = 0.05  # p-value threshold
        self.correlation_threshold = 0.3  # Low correlation is suspicious
    
    async def analyze(self, image_data: bytes, timeout: int = 30) -> StegoAnalysis:
        """
        Perform comprehensive steganography analysis.
        
        Args:
            image_data: Image as bytes
            timeout: Analysis timeout in seconds
            
        Returns:
            Steganography analysis result
        """
        start_time = time.time()
        
        try:
            # Check cache
            if self.cache:
                cache_key = SecurityAnalysisCache.generate_content_hash(image_data)
                cached = self.cache.get(cache_key)
                if cached:
                    logger.debug("Steganography analysis cache hit")
                    return cached
            
            # Load image
            image = Image.open(io.BytesIO(image_data))
            
            # Convert to RGB if needed
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            # Convert to numpy array
            img_array = np.array(image)
            
            # Run analyses in parallel with timeout
            try:
                analyses = await asyncio.wait_for(
                    asyncio.gather(
                        self._analyze_lsb_patterns(img_array),
                        self._analyze_frequency_domain(img_array),
                        self._analyze_noise_profile(img_array),
                        self._analyze_color_correlations(img_array),
                        return_exceptions=True
                    ),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Steganography analysis timed out after {timeout}s")
                return self._create_timeout_result(time.time() - start_time)
            
            # Unpack results
            lsb_analysis = analyses[0] if not isinstance(analyses[0], Exception) else None
            freq_score = analyses[1] if not isinstance(analyses[1], Exception) else 0.0
            noise_score = analyses[2] if not isinstance(analyses[2], Exception) else 0.0
            corr_score = analyses[3] if not isinstance(analyses[3], Exception) else 0.0
            
            # Calculate overall score
            overall_score = self._calculate_overall_score(
                lsb_analysis, freq_score, noise_score, corr_score
            )
            
            # Determine threat level
            threat_level = self._determine_threat_level(overall_score)
            
            analysis_time = (time.time() - start_time) * 1000
            
            result = StegoAnalysis(
                lsb_analysis=lsb_analysis,
                frequency_analysis_score=freq_score,
                noise_profile_score=noise_score,
                color_correlation_score=corr_score,
                overall_stego_score=overall_score,
                threat_level=threat_level,
                analysis_time_ms=analysis_time
            )
            
            # Cache result
            if self.cache:
                self.cache.set(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Steganography analysis failed: {e}")
            return self._create_error_result(str(e), time.time() - start_time)
    
    async def _analyze_lsb_patterns(self, img_array: np.ndarray) -> Optional[LSBAnalysis]:
        """
        Analyze LSB patterns for steganography indicators.
        
        Args:
            img_array: Image as numpy array
            
        Returns:
            LSB analysis result
        """
        try:
            # Calculate entropy of LSB planes
            entropy_scores = calculate_lsb_entropy(img_array)
            
            # Chi-square tests for each channel
            chi_square_scores = []
            for channel in range(img_array.shape[2]):
                lsb_plane = img_array[:, :, channel] & 1
                chi2_stat, p_value = calculate_chi_square(lsb_plane)
                chi_square_scores.append(p_value)
            
            # Analyze bit plane complexity
            correlation_scores = []
            for channel in range(img_array.shape[2]):
                complexity = analyze_bit_plane_complexity(img_array[:, :, channel], bit_position=0)
                correlation_scores.append(complexity)
            
            # Determine if anomaly detected
            high_entropy = any(e > self.lsb_entropy_threshold for e in entropy_scores)
            low_p_value = any(p < self.chi_square_threshold for p in chi_square_scores)
            anomaly_detected = high_entropy or low_p_value
            
            # Calculate confidence
            confidence = self._calculate_lsb_confidence(
                entropy_scores, chi_square_scores, correlation_scores
            )
            
            return LSBAnalysis(
                chi_square_scores=chi_square_scores,
                entropy_scores=entropy_scores,
                correlation_scores=correlation_scores,
                anomaly_detected=anomaly_detected,
                confidence=confidence
            )
            
        except Exception as e:
            logger.error(f"LSB analysis failed: {e}")
            return None
    
    async def _analyze_frequency_domain(self, img_array: np.ndarray) -> float:
        """
        Analyze frequency domain for anomalies.
        
        Uses simplified frequency analysis without FFT for CPU efficiency.
        
        Args:
            img_array: Image as numpy array
            
        Returns:
            Frequency analysis score (0-1)
        """
        try:
            # Simplified frequency analysis using gradient
            scores = []
            for channel in range(img_array.shape[2]):
                channel_data = img_array[:, :, channel].astype(float)
                
                # Calculate gradients
                grad_x = np.diff(channel_data, axis=1)
                grad_y = np.diff(channel_data, axis=0)
                
                # High frequency content in LSB plane
                lsb_plane = img_array[:, :, channel] & 1
                lsb_grad_x = np.diff(lsb_plane.astype(float), axis=1)
                lsb_grad_y = np.diff(lsb_plane.astype(float), axis=0)
                
                # Calculate variance ratio
                main_var = np.var(grad_x) + np.var(grad_y)
                lsb_var = np.var(lsb_grad_x) + np.var(lsb_grad_y)
                
                # High LSB variance relative to main is suspicious
                if main_var > 0:
                    ratio = lsb_var / main_var
                    scores.append(min(ratio, 1.0))
                else:
                    scores.append(0.0)
            
            return float(np.mean(scores))
            
        except Exception as e:
            logger.error(f"Frequency analysis failed: {e}")
            return 0.0
    
    async def _analyze_noise_profile(self, img_array: np.ndarray) -> float:
        """
        Analyze noise patterns for anomalies.
        
        Args:
            img_array: Image as numpy array
            
        Returns:
            Noise profile score (0-1)
        """
        try:
            scores = []
            for channel in range(img_array.shape[2]):
                channel_data = img_array[:, :, channel]
                
                # Extract LSB as "noise"
                lsb = channel_data & 1
                
                # Natural noise should have certain statistical properties
                # Calculate local variance in small blocks
                block_size = 8
                variances = []
                
                for i in range(0, lsb.shape[0] - block_size, block_size):
                    for j in range(0, lsb.shape[1] - block_size, block_size):
                        block = lsb[i:i+block_size, j:j+block_size]
                        variances.append(np.var(block))
                
                # Uniform variance across blocks is suspicious
                if variances:
                    var_of_vars = np.var(variances)
                    # Low variance of variances = suspicious
                    score = 1.0 - min(var_of_vars / 0.25, 1.0)  # Normalize
                    scores.append(score)
            
            return float(np.mean(scores)) if scores else 0.0
            
        except Exception as e:
            logger.error(f"Noise analysis failed: {e}")
            return 0.0
    
    async def _analyze_color_correlations(self, img_array: np.ndarray) -> float:
        """
        Analyze correlations between color channels.
        
        Args:
            img_array: Image as numpy array
            
        Returns:
            Correlation score (0-1)
        """
        try:
            if img_array.shape[2] < 3:
                return 0.0
            
            # Calculate correlations between channel LSB planes
            r_lsb = img_array[:, :, 0] & 1
            g_lsb = img_array[:, :, 1] & 1
            b_lsb = img_array[:, :, 2] & 1
            
            # Natural images have some correlation between channels
            # Embedded data reduces this correlation
            corr_rg = abs(calculate_correlation_coefficient(r_lsb, g_lsb))
            corr_rb = abs(calculate_correlation_coefficient(r_lsb, b_lsb))
            corr_gb = abs(calculate_correlation_coefficient(g_lsb, b_lsb))
            
            avg_correlation = (corr_rg + corr_rb + corr_gb) / 3
            
            # Low correlation is suspicious
            if avg_correlation < self.correlation_threshold:
                score = 1.0 - (avg_correlation / self.correlation_threshold)
            else:
                score = 0.0
            
            return float(score)
            
        except Exception as e:
            logger.error(f"Correlation analysis failed: {e}")
            return 0.0
    
    def _calculate_lsb_confidence(
        self,
        entropy_scores: list,
        chi_scores: list,
        complexity_scores: list
    ) -> float:
        """Calculate confidence in LSB analysis."""
        # More indicators = higher confidence
        indicators = 0
        total_checks = 0
        
        for entropy in entropy_scores:
            total_checks += 1
            if entropy > self.lsb_entropy_threshold:
                indicators += 1
        
        for p_val in chi_scores:
            total_checks += 1
            if p_val < self.chi_square_threshold:
                indicators += 1
        
        confidence = indicators / total_checks if total_checks > 0 else 0.0
        return float(confidence)
    
    def _calculate_overall_score(
        self,
        lsb_analysis: Optional[LSBAnalysis],
        freq_score: float,
        noise_score: float,
        corr_score: float
    ) -> float:
        """Calculate overall steganography score."""
        scores = []
        weights = []
        
        # LSB analysis (40% weight)
        if lsb_analysis and lsb_analysis.anomaly_detected:
            scores.append(lsb_analysis.confidence)
            weights.append(0.4)
        
        # Frequency analysis (25% weight)
        if freq_score > 0:
            scores.append(freq_score)
            weights.append(0.25)
        
        # Noise profile (20% weight)
        if noise_score > 0:
            scores.append(noise_score)
            weights.append(0.2)
        
        # Color correlation (15% weight)
        if corr_score > 0:
            scores.append(corr_score)
            weights.append(0.15)
        
        if not scores:
            return 0.0
        
        # Weighted average
        total_weight = sum(weights)
        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        
        return float(weighted_sum / total_weight) if total_weight > 0 else 0.0
    
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
    
    def _create_timeout_result(self, elapsed_time: float) -> StegoAnalysis:
        """Create result for timeout case."""
        return StegoAnalysis(
            lsb_analysis=None,
            frequency_analysis_score=0.0,
            noise_profile_score=0.0,
            color_correlation_score=0.0,
            overall_stego_score=0.5,  # Moderate score for timeout
            threat_level=ThreatLevel.MEDIUM,
            analysis_time_ms=elapsed_time * 1000
        )
    
    def _create_error_result(self, error: str, elapsed_time: float) -> StegoAnalysis:
        """Create result for error case."""
        logger.error(f"Steganography detection error: {error}")
        return StegoAnalysis(
            lsb_analysis=None,
            frequency_analysis_score=0.0,
            noise_profile_score=0.0,
            color_correlation_score=0.0,
            overall_stego_score=0.0,
            threat_level=ThreatLevel.NONE,
            analysis_time_ms=elapsed_time * 1000
        )
