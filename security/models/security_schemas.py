"""
Pydantic data models for security analysis results.

These schemas define the structure of security reports and threat assessments.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAnomaly(BaseModel):
    """Detected security anomaly."""
    type: str = Field(..., description="Type of anomaly detected")
    severity: ThreatLevel = Field(..., description="Severity level")
    description: str = Field(..., description="Human-readable description")
    confidence: float = Field(..., ge=0, le=1, description="Detection confidence (0-1)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


class SecurityRecommendation(BaseModel):
    """Security recommendation based on detected threats."""
    action: str = Field(..., description="Recommended action")
    priority: str = Field(..., description="Priority level (high/medium/low)")
    reasoning: str = Field(..., description="Explanation for the recommendation")


class LSBAnalysis(BaseModel):
    """Results of LSB (Least Significant Bit) analysis."""
    chi_square_scores: List[float] = Field(..., description="Chi-square test results per channel")
    entropy_scores: List[float] = Field(..., description="Entropy scores per channel")
    correlation_scores: List[float] = Field(..., description="Correlation analysis scores")
    anomaly_detected: bool = Field(..., description="Whether anomaly was detected")
    confidence: float = Field(..., ge=0, le=1, description="Overall confidence")


class StegoAnalysis(BaseModel):
    """Comprehensive steganography analysis result."""
    lsb_analysis: Optional[LSBAnalysis] = Field(None, description="LSB analysis results")
    frequency_analysis_score: float = Field(..., ge=0, le=1, description="Frequency domain analysis")
    noise_profile_score: float = Field(..., ge=0, le=1, description="Noise pattern analysis")
    color_correlation_score: float = Field(..., ge=0, le=1, description="Color channel correlation")
    overall_stego_score: float = Field(..., ge=0, le=1, description="Overall steganography score")
    threat_level: ThreatLevel = Field(..., description="Assessed threat level")
    analysis_time_ms: float = Field(..., description="Time taken for analysis")


class ThreatVector(BaseModel):
    """Individual threat vector analysis."""
    type: str = Field(..., description="Type of threat (zero_width, homoglyph, etc.)")
    threat_score: float = Field(..., ge=0, le=1, description="Threat score (0-1)")
    details: str = Field(..., description="Details about the detected threat")
    pattern_analysis: Optional[Dict[str, Any]] = Field(None, description="Pattern analysis results")
    samples: List[str] = Field(default_factory=list, description="Sample instances of the threat")


class UnicodeThreatReport(BaseModel):
    """Comprehensive Unicode threat analysis report."""
    threat_vectors: List[ThreatVector] = Field(..., description="Individual threat vectors")
    overall_threat_score: float = Field(..., ge=0, le=1, description="Overall threat score")
    threat_level: ThreatLevel = Field(..., description="Overall threat level")
    recommendations: List[SecurityRecommendation] = Field(..., description="Security recommendations")
    analysis_time_ms: float = Field(..., description="Time taken for analysis")


class ConflictAnalysis(BaseModel):
    """Semantic conflict analysis results."""
    conflict_score: float = Field(..., ge=0, le=1, description="Overall conflict score")
    detected_conflicts: List[str] = Field(default_factory=list, description="List of detected conflicts")
    similarity_metrics: Dict[str, float] = Field(default_factory=dict, description="Similarity scores")
    confidence: float = Field(..., ge=0, le=1, description="Analysis confidence")
    threat_level: ThreatLevel = Field(default=ThreatLevel.NONE, description="Assessed threat level")
    error: Optional[str] = Field(None, description="Error message if analysis failed")


class BehavioralProfile(BaseModel):
    """Behavioral pattern analysis profile."""
    request_frequency: float = Field(..., description="Request frequency (requests/second)")
    pattern_complexity: float = Field(..., ge=0, le=1, description="Complexity of input patterns")
    anomaly_score: float = Field(..., ge=0, le=1, description="Behavioral anomaly score")
    threat_level: ThreatLevel = Field(..., description="Behavioral threat level")
    temporal_patterns: Dict[str, Any] = Field(default_factory=dict, description="Temporal patterns")


class SecurityReport(BaseModel):
    """Comprehensive security analysis report."""
    # Individual analysis scores
    steganography_score: float = Field(0.0, ge=0, le=1, description="Steganography detection score")
    unicode_threat_score: float = Field(0.0, ge=0, le=1, description="Unicode threat score")
    semantic_conflict_score: float = Field(0.0, ge=0, le=1, description="Semantic conflict score")
    behavioral_anomaly_score: float = Field(0.0, ge=0, le=1, description="Behavioral anomaly score")
    
    # Overall assessment
    overall_threat_score: float = Field(0.0, ge=0, le=1, description="Combined threat score")
    overall_threat_level: ThreatLevel = Field(ThreatLevel.NONE, description="Overall threat level")
    
    # Detailed results
    detected_anomalies: List[SecurityAnomaly] = Field(default_factory=list, description="All detected anomalies")
    recommendations: List[SecurityRecommendation] = Field(default_factory=list, description="Security recommendations")
    
    # Metadata
    analysis_time_ms: float = Field(..., description="Total analysis time")
    analysis_enabled: Dict[str, bool] = Field(default_factory=dict, description="Which analyses were enabled")
    
    # Detailed sub-reports (optional)
    stego_analysis: Optional[StegoAnalysis] = Field(None, description="Detailed steganography analysis")
    unicode_analysis: Optional[UnicodeThreatReport] = Field(None, description="Detailed Unicode analysis")
    conflict_analysis: Optional[ConflictAnalysis] = Field(None, description="Detailed conflict analysis")
    behavioral_profile: Optional[BehavioralProfile] = Field(None, description="Behavioral profile")


class SecurityMetadata(BaseModel):
    """Metadata about security processing."""
    security_version: str = Field("1.0.0", description="Security module version")
    analyzers_used: List[str] = Field(..., description="List of analyzers that ran")
    cache_hit: bool = Field(False, description="Whether results were cached")
    performance_impact_ms: float = Field(..., description="Additional latency from security checks")
