"""
Behavioral analysis module.

Analyzes behavioral patterns to detect:
- Request frequency anomalies
- Pattern complexity in inputs
- Temporal patterns
- Coordinated attacks
"""

import time
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field

from ..models.security_schemas import (
    BehavioralProfile,
    ThreatLevel,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RequestMetrics:
    """Metrics for tracking request patterns."""
    timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    pattern_hashes: deque = field(default_factory=lambda: deque(maxlen=50))
    total_requests: int = 0
    suspicious_requests: int = 0


class BehavioralAnalyzer:
    """
    Behavioral pattern analyzer for detecting anomalous usage.
    
    Tracks request patterns over time to identify potential
    coordinated attacks or abuse.
    """
    
    def __init__(self, window_seconds: int = 60):
        """
        Initialize analyzer.
        
        Args:
            window_seconds: Time window for rate calculations
        """
        self.window_seconds = window_seconds
        self.client_metrics: Dict[str, RequestMetrics] = defaultdict(RequestMetrics)
        
        # Thresholds
        self.high_frequency_threshold = 10  # requests per minute
        self.pattern_repetition_threshold = 0.7
        self.burst_threshold = 5  # requests in 1 second
    
    async def analyze(
        self,
        client_id: str,
        request_data: Any,
        request_hash: Optional[str] = None
    ) -> BehavioralProfile:
        """
        Analyze behavioral patterns for a client.
        
        Args:
            client_id: Client identifier
            request_data: Request data to analyze
            request_hash: Optional hash of request pattern
            
        Returns:
            Behavioral profile with threat assessment
        """
        try:
            now = time.time()
            metrics = self.client_metrics[client_id]
            
            # Record request
            metrics.timestamps.append(now)
            metrics.total_requests += 1
            
            if request_hash:
                metrics.pattern_hashes.append(request_hash)
            
            # Calculate request frequency
            request_frequency = self._calculate_frequency(metrics, now)
            
            # Analyze pattern complexity
            pattern_complexity = self._analyze_pattern_complexity(metrics)
            
            # Detect temporal anomalies
            temporal_patterns = self._analyze_temporal_patterns(metrics, now)
            
            # Calculate anomaly score
            anomaly_score = self._calculate_anomaly_score(
                request_frequency,
                pattern_complexity,
                temporal_patterns
            )
            
            # Determine threat level
            threat_level = self._determine_threat_level(anomaly_score)
            
            # Update suspicious request count
            if anomaly_score > 0.6:
                metrics.suspicious_requests += 1
            
            return BehavioralProfile(
                request_frequency=request_frequency,
                pattern_complexity=pattern_complexity,
                anomaly_score=anomaly_score,
                threat_level=threat_level,
                temporal_patterns=temporal_patterns
            )
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            return BehavioralProfile(
                request_frequency=0.0,
                pattern_complexity=0.0,
                anomaly_score=0.0,
                threat_level=ThreatLevel.NONE,
                temporal_patterns={}
            )
    
    def _calculate_frequency(self, metrics: RequestMetrics, now: float) -> float:
        """
        Calculate request frequency (requests per second).
        
        Args:
            metrics: Client metrics
            now: Current timestamp
            
        Returns:
            Requests per second
        """
        # Filter timestamps within window
        cutoff = now - self.window_seconds
        recent_timestamps = [ts for ts in metrics.timestamps if ts >= cutoff]
        
        if not recent_timestamps:
            return 0.0
        
        # Calculate frequency
        time_span = now - min(recent_timestamps)
        if time_span > 0:
            frequency = len(recent_timestamps) / time_span
        else:
            frequency = len(recent_timestamps)
        
        return frequency
    
    def _analyze_pattern_complexity(self, metrics: RequestMetrics) -> float:
        """
        Analyze complexity/diversity of request patterns.
        
        Args:
            metrics: Client metrics
            
        Returns:
            Pattern complexity score (0-1)
        """
        if not metrics.pattern_hashes:
            return 0.5
        
        # Calculate uniqueness
        unique_patterns = len(set(metrics.pattern_hashes))
        total_patterns = len(metrics.pattern_hashes)
        
        uniqueness_ratio = unique_patterns / total_patterns
        
        # Low uniqueness (high repetition) is suspicious
        if uniqueness_ratio < self.pattern_repetition_threshold:
            complexity = 1.0 - uniqueness_ratio
        else:
            complexity = 0.0
        
        return complexity
    
    def _analyze_temporal_patterns(self, metrics: RequestMetrics, now: float) -> Dict[str, Any]:
        """
        Analyze temporal patterns in requests.
        
        Args:
            metrics: Client metrics
            now: Current timestamp
            
        Returns:
            Temporal pattern analysis
        """
        patterns = {}
        
        if len(metrics.timestamps) < 2:
            return patterns
        
        # Calculate inter-arrival times
        timestamps_list = list(metrics.timestamps)
        inter_arrival = [
            timestamps_list[i] - timestamps_list[i-1]
            for i in range(1, len(timestamps_list))
        ]
        
        if inter_arrival:
            # Average inter-arrival time
            avg_interval = sum(inter_arrival) / len(inter_arrival)
            patterns['avg_interval_seconds'] = avg_interval
            
            # Detect bursts
            burst_count = sum(1 for interval in inter_arrival if interval < 1.0)
            patterns['burst_count'] = burst_count
            patterns['has_bursts'] = burst_count >= self.burst_threshold
            
            # Calculate regularity (variance in intervals)
            if len(inter_arrival) > 1:
                variance = sum((x - avg_interval) ** 2 for x in inter_arrival) / len(inter_arrival)
                # Low variance = regular pattern = potentially automated
                patterns['interval_variance'] = variance
                patterns['is_regular'] = variance < 1.0
        
        # Recent activity spike
        recent_1s = sum(1 for ts in timestamps_list if now - ts < 1.0)
        patterns['requests_last_second'] = recent_1s
        patterns['is_spike'] = recent_1s >= self.burst_threshold
        
        return patterns
    
    def _calculate_anomaly_score(
        self,
        frequency: float,
        complexity: float,
        temporal_patterns: Dict[str, Any]
    ) -> float:
        """
        Calculate overall behavioral anomaly score.
        
        Args:
            frequency: Request frequency
            complexity: Pattern complexity
            temporal_patterns: Temporal analysis results
            
        Returns:
            Anomaly score (0-1)
        """
        score = 0.0
        
        # High frequency
        if frequency > self.high_frequency_threshold:
            score += 0.3
        
        # High pattern repetition
        score += complexity * 0.25
        
        # Burst behavior
        if temporal_patterns.get('has_bursts', False):
            score += 0.25
        
        # Regular automated pattern
        if temporal_patterns.get('is_regular', False):
            score += 0.2
        
        return min(score, 1.0)
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Determine threat level from anomaly score."""
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
    
    def get_client_stats(self, client_id: str) -> Dict[str, Any]:
        """Get statistics for a specific client."""
        if client_id not in self.client_metrics:
            return {}
        
        metrics = self.client_metrics[client_id]
        
        return {
            'total_requests': metrics.total_requests,
            'suspicious_requests': metrics.suspicious_requests,
            'recent_request_count': len(metrics.timestamps),
            'unique_patterns': len(set(metrics.pattern_hashes)) if metrics.pattern_hashes else 0,
        }
    
    def cleanup_old_data(self, max_age_seconds: int = 3600):
        """
        Clean up old client data.
        
        Args:
            max_age_seconds: Maximum age to retain
        """
        now = time.time()
        cutoff = now - max_age_seconds
        
        clients_to_remove = []
        
        for client_id, metrics in self.client_metrics.items():
            if metrics.timestamps:
                most_recent = max(metrics.timestamps)
                if most_recent < cutoff:
                    clients_to_remove.append(client_id)
        
        for client_id in clients_to_remove:
            del self.client_metrics[client_id]
        
        logger.info(f"Cleaned up {len(clients_to_remove)} inactive clients")


# Global analyzer instance
_global_analyzer: Optional[BehavioralAnalyzer] = None


def get_global_analyzer() -> BehavioralAnalyzer:
    """Get or create global analyzer instance."""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = BehavioralAnalyzer()
    return _global_analyzer
