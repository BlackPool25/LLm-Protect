"""
Core type definitions for the Image + Emoji Security Guard System.

This module defines all Pydantic models and type structures used throughout
the security guard pipeline, ensuring type safety and data validation.
"""

from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
from enum import Enum


# ============================================================================
# Input Types
# ============================================================================

class IncomingRequest(BaseModel):
    """
    Normalized input request structure for the security guard system.
    
    Attributes:
        text: Optional user text message
        image_bytes: Optional raw image data
        metadata: Optional request metadata (userId, requestId, timestamp, etc.)
    """
    text: Optional[str] = Field(None, description="User's text message")
    image_bytes: Optional[bytes] = Field(None, description="Raw image data")
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Request metadata (userId, requestId, timestamp)"
    )


# ============================================================================
# Image Pipeline Types
# ============================================================================

class ImageSanityCheck(BaseModel):
    """
    Result of image sanity validation.
    
    Attributes:
        is_valid: Whether the image passed validation
        mime_type: Detected MIME type
        width: Image width in pixels
        height: Image height in pixels
        size_bytes: File size in bytes
        format: Image format (PNG, JPEG, etc.)
        error: Error message if validation failed
    """
    is_valid: bool
    mime_type: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    size_bytes: Optional[int] = None
    format: Optional[str] = None
    error: Optional[str] = None


class StegoFeature(BaseModel):
    """
    Steganography analysis features from image.
    
    Attributes:
        stego_score: Overall steganography score (0-1)
        lsb_stats: LSB analysis statistics
        chi_square: Chi-square test result
        bit_plane_entropy: Bit plane entropy values
        noise_profile_score: Noise pattern analysis score
        correlation_score: Color channel correlation score
    """
    stego_score: float = Field(..., ge=0.0, le=1.0, description="Overall stego score")
    lsb_stats: Optional[Dict[str, float]] = Field(default_factory=dict)
    chi_square: Optional[float] = None
    bit_plane_entropy: Optional[float] = None
    noise_profile_score: Optional[float] = None
    correlation_score: Optional[float] = None


class ImageStats(BaseModel):
    """
    Basic image statistics.
    
    Attributes:
        width: Image width
        height: Image height
        aspect_ratio: Width/height ratio
        mean_brightness: Average brightness (0-255)
        channels: Number of color channels
    """
    width: int
    height: int
    aspect_ratio: float
    mean_brightness: float = Field(..., ge=0.0, le=255.0)
    channels: int = Field(default=3, description="Number of color channels")


class ImageFeaturePack(BaseModel):
    """
    Complete feature pack from image pipeline.
    
    Attributes:
        stego_score: Steganography score (0-1)
        image_embedding: Image embedding vector (128d)
        image_stats: Basic image statistics
        hash: SHA-256 hash of image
        embedding_is_stub: Flag indicating if embedding is from stub
    """
    stego_score: float = Field(..., ge=0.0, le=1.0)
    image_embedding: List[float] = Field(..., min_items=128, max_items=128)
    image_stats: ImageStats
    hash: str = Field(..., description="SHA-256 hash of image")
    embedding_is_stub: bool = Field(
        default=True,
        description="True if embedding is from stub, False if from real model"
    )


# ============================================================================
# Emoji / Text Pipeline Types
# ============================================================================

class EmojiExtractionResult(BaseModel):
    """
    Result of emoji extraction and text normalization.
    
    Attributes:
        emojis: List of extracted emoji sequences
        normalized_text: Text with emojis normalized
        stripped_text: Text with emojis completely removed
        emoji_count: Total number of emojis found
    """
    emojis: List[str] = Field(default_factory=list)
    normalized_text: str
    stripped_text: str
    emoji_count: int = Field(default=0, ge=0)


class EmojiPatternFeatures(BaseModel):
    """
    Features from emoji pattern analysis.
    
    Attributes:
        repetition_score: Score for emoji repetition (0-1)
        cipher_like: Whether sequence looks like a cipher
        mixed_script_with_emoji: Mixed script + emoji pattern detected
        suspicious_sequences: List of suspicious emoji sequences
        pattern_complexity: Overall pattern complexity score (0-1)
    """
    repetition_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cipher_like: bool = Field(default=False)
    mixed_script_with_emoji: bool = Field(default=False)
    suspicious_sequences: List[str] = Field(default_factory=list)
    pattern_complexity: float = Field(default=0.0, ge=0.0, le=1.0)


class UnicodeThreatFeatures(BaseModel):
    """
    Features from Unicode threat detection.
    
    Attributes:
        has_zero_width: Zero-width characters detected
        has_bidi_override: Bidirectional override detected
        has_homoglyphs: Homoglyph substitution detected
        threat_flags: List of specific threat types detected
        zero_width_count: Number of zero-width characters
        bidi_override_count: Number of bidi override characters
        homoglyph_count: Number of potential homoglyphs
        overall_unicode_threat_score: Combined Unicode threat score (0-1)
    """
    has_zero_width: bool = Field(default=False)
    has_bidi_override: bool = Field(default=False)
    has_homoglyphs: bool = Field(default=False)
    threat_flags: List[str] = Field(default_factory=list)
    zero_width_count: int = Field(default=0, ge=0)
    bidi_override_count: int = Field(default=0, ge=0)
    homoglyph_count: int = Field(default=0, ge=0)
    overall_unicode_threat_score: float = Field(default=0.0, ge=0.0, le=1.0)


class EmojiFeaturePack(BaseModel):
    """
    Complete feature pack from emoji/text pipeline.
    
    Attributes:
        emoji_risk_score: Overall emoji risk score (0-1)
        emoji_categories: List of triggered risk categories
        emoji_sequence: Extracted emoji sequences
        pattern_features: Emoji pattern analysis features
        unicode_threats: Unicode threat detection features
    """
    emoji_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    emoji_categories: List[str] = Field(default_factory=list)
    emoji_sequence: List[str] = Field(default_factory=list)
    pattern_features: EmojiPatternFeatures
    unicode_threats: UnicodeThreatFeatures


# ============================================================================
# Fusion Layer Types
# ============================================================================

class FusionMetadata(BaseModel):
    """
    Metadata about the fusion process.
    
    Attributes:
        has_image: Whether image was present in request
        has_emojis: Whether emojis were present in text
        text_length: Length of text input
        hash: Combined hash of inputs
    """
    has_image: bool
    has_emojis: bool
    text_length: int = Field(ge=0)
    hash: str = Field(..., description="Combined hash of all inputs")


class FusionFeatures(BaseModel):
    """
    Fused features from all pipelines.
    
    Attributes:
        vector: Combined feature vector (all numeric features concatenated)
        image_features: Image feature pack (if image present)
        emoji_features: Emoji feature pack (if text present)
        metadata: Fusion metadata
    """
    vector: List[float] = Field(..., description="Combined normalized feature vector")
    image_features: Optional[ImageFeaturePack] = None
    emoji_features: Optional[EmojiFeaturePack] = None
    metadata: FusionMetadata


# ============================================================================
# Anomaly Detection Types
# ============================================================================

class Verdict(str, Enum):
    """Anomaly detection verdict."""
    PASS = "pass"
    BORDERLINE = "borderline"
    FAIL = "fail"


class AnomalyDecision(BaseModel):
    """
    Anomaly detection decision.
    
    Attributes:
        verdict: Pass, borderline, or fail
        anomaly_score: Overall anomaly score (0-1)
        reasons: Human-readable reasons for the decision
        triggered_rules: List of specific rules that triggered
    """
    verdict: Verdict
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    triggered_rules: List[str] = Field(default_factory=list)


# ============================================================================
# Decision Layer Types
# ============================================================================

class GuardAction(str, Enum):
    """Guard decision action."""
    ALLOW = "allow"
    REWRITE = "rewrite"
    BLOCK = "block"


class GuardResult(BaseModel):
    """
    Final result from the security guard system.
    
    Attributes:
        action: Allow, rewrite, or block
        reasons: Human-readable reasons for the decision
        anomaly_score: Overall anomaly score (0-1)
        sanitized_text: Text with invisible Unicode threats removed (if allowed)
        message: User-facing message (for rewrite/block actions)
        debug: Optional debug information (only if debug mode enabled)
    """
    action: GuardAction
    reasons: List[str] = Field(default_factory=list)
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    sanitized_text: str = Field(default="")
    message: Optional[str] = Field(
        None,
        description="User-facing message for rewrite/block actions"
    )
    debug: Optional[Dict[str, Any]] = Field(
        None,
        description="Debug information (only in debug mode)"
    )


# ============================================================================
# Export all types
# ============================================================================

__all__ = [
    # Input types
    "IncomingRequest",
    
    # Image pipeline types
    "ImageSanityCheck",
    "StegoFeature",
    "ImageStats",
    "ImageFeaturePack",
    
    # Emoji/text pipeline types
    "EmojiExtractionResult",
    "EmojiPatternFeatures",
    "UnicodeThreatFeatures",
    "EmojiFeaturePack",
    
    # Fusion types
    "FusionMetadata",
    "FusionFeatures",
    
    # Anomaly detection types
    "Verdict",
    "AnomalyDecision",
    
    # Decision layer types
    "GuardAction",
    "GuardResult",
]
