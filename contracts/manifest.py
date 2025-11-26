"""
Pipeline Manifest Contract.

This module defines the shared manifest object used across all layers of the
LLM-Protect pipeline. Each layer reads from and updates specific fields.

Flow: Layer 0 → Input Prep → Image Processing → (Layer 1/2)

Design Principles:
- Immutable except for designated update fields
- Each layer only modifies its own result section
- Manifest ID tracks the request through the pipeline
- Timestamps enable latency monitoring
"""

import uuid
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    """Unified scan status across all layers."""
    CLEAN = "CLEAN"
    CLEAN_CODE = "CLEAN_CODE"
    REJECTED = "REJECTED"
    WARN = "WARN"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ERROR = "ERROR"
    PENDING = "PENDING"


class Severity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# ============================================================================
# Hash Information
# ============================================================================

class HashInfo(BaseModel):
    """Hash information for content integrity."""
    text_sha256: Optional[str] = Field(None, description="SHA256 of raw text")
    clean_text_sha256: Optional[str] = Field(None, description="SHA256 of normalized text")
    image_sha256: Optional[str] = Field(None, description="SHA256 of image content")
    image_phash: Optional[str] = Field(None, description="Perceptual hash of image")
    hmac_signature: Optional[str] = Field(None, description="HMAC signature for verification")
    external_chunks_hmacs: List[str] = Field(default_factory=list, description="HMACs for external chunks")


# ============================================================================
# Embedding Information
# ============================================================================

class EmbeddingInfo(BaseModel):
    """Embedding vectors and fingerprints."""
    text_embedding_hash: Optional[str] = Field(None, description="Hash of text embedding vector")
    text_embedding_vector: Optional[List[float]] = Field(None, description="Full text embedding vector")
    image_embedding_hash: Optional[str] = Field(None, description="Hash of image embedding")
    image_caption: Optional[str] = Field(None, description="Vision model caption")
    model_name: Optional[str] = Field(None, description="Embedding model used")


# ============================================================================
# Attachment Information
# ============================================================================

class AttachmentInfo(BaseModel):
    """Information about an attachment (file, image, etc.)."""
    id: str = Field(..., description="Attachment identifier")
    type: str = Field(..., description="Attachment type: file, image, emoji")
    filename: Optional[str] = Field(None, description="Original filename")
    hash: Optional[str] = Field(None, description="Content hash")
    size_bytes: Optional[int] = Field(None, description="Size in bytes")
    format: Optional[str] = Field(None, description="File format/extension")
    dimensions: Optional[tuple] = Field(None, description="Image dimensions (w, h)")
    extracted_text: Optional[str] = Field(None, description="Text extracted from attachment")
    description: Optional[str] = Field(None, description="AI-generated description")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


# ============================================================================
# Flag Information
# ============================================================================

class FlagInfo(BaseModel):
    """Security and processing flags."""
    # Layer 0 flags
    has_injection_attempt: bool = Field(False)
    has_jailbreak_attempt: bool = Field(False)
    has_obfuscation: bool = Field(False)
    code_detected: bool = Field(False)
    
    # Input Prep flags
    hmac_verified: bool = Field(False)
    unicode_normalized: bool = Field(False)
    zero_width_removed: bool = Field(False)
    homoglyphs_replaced: bool = Field(False)
    
    # Image Processing flags
    steganography_detected: bool = Field(False)
    suspicious_metadata: bool = Field(False)
    ocr_performed: bool = Field(False)
    high_entropy: bool = Field(False)
    
    # Emoji flags
    has_emojis: bool = Field(False)
    emoji_count: int = Field(0)
    
    # Additional flags
    custom_flags: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Layer Results
# ============================================================================

class Layer0Result(BaseModel):
    """Results from Layer 0 (Heuristics/Regex) scanning."""
    status: ScanStatus = Field(ScanStatus.PENDING)
    score: float = Field(0.0, ge=0.0, le=1.0, description="Suspicion score 0-1")
    processing_time_ms: float = Field(0.0)
    rule_id: Optional[str] = Field(None)
    dataset: Optional[str] = Field(None)
    severity: Optional[Severity] = Field(None)
    matched_preview: Optional[str] = Field(None, description="Redacted preview of match")
    audit_token: Optional[str] = Field(None)
    note: Optional[str] = Field(None)
    
    # Detailed detection info
    patterns_detected: List[str] = Field(default_factory=list)
    prefilter_passed: bool = Field(True)
    normalization_applied: bool = Field(False)


class InputPrepResult(BaseModel):
    """Results from Input Preparation layer."""
    status: ScanStatus = Field(ScanStatus.PENDING)
    score: float = Field(0.0, ge=0.0, le=1.0, description="Prep confidence score")
    processing_time_ms: float = Field(0.0)
    
    # Normalization info
    original_char_count: int = Field(0)
    normalized_char_count: int = Field(0)
    token_estimate: int = Field(0)
    
    # External data info
    external_chunks_count: int = Field(0)
    hmacs_generated: int = Field(0)
    hmacs_verified: int = Field(0)
    
    # Emoji processing
    emoji_count: int = Field(0)
    emoji_descriptions: List[str] = Field(default_factory=list)
    
    # Unicode analysis
    zero_width_found: int = Field(0)
    invisible_chars_found: int = Field(0)
    homoglyphs_replaced: int = Field(0)
    unicode_obfuscation_detected: bool = Field(False)
    
    # Heuristic flags
    has_long_base64: bool = Field(False)
    has_system_delimiter: bool = Field(False)
    has_suspicious_keywords: bool = Field(False)
    suspicious_score: float = Field(0.0)
    detected_patterns: List[str] = Field(default_factory=list)
    
    note: Optional[str] = Field(None)


class ImageProcessingResult(BaseModel):
    """Results from Image Processing layer."""
    status: ScanStatus = Field(ScanStatus.PENDING)
    score: float = Field(0.0, ge=0.0, le=1.0, description="Image safety score")
    processing_time_ms: float = Field(0.0)
    
    # Image metadata
    format: Optional[str] = Field(None)
    dimensions: Optional[tuple] = Field(None)
    size_bytes: Optional[int] = Field(None)
    
    # Perceptual hashing
    phash: Optional[str] = Field(None)
    phash_match_known: bool = Field(False)
    
    # EXIF analysis
    exif_extracted: bool = Field(False)
    exif_suspicious: bool = Field(False)
    embedded_text_from_exif: Optional[str] = Field(None)
    
    # OCR results
    ocr_performed: bool = Field(False)
    ocr_text: Optional[str] = Field(None)
    ocr_confidence: Optional[float] = Field(None)
    
    # Steganography detection
    stego_score: float = Field(0.0)
    stego_detected: bool = Field(False)
    entropy: Optional[float] = Field(None)
    entropy_suspicious: bool = Field(False)
    
    # Vision captioning
    caption: Optional[str] = Field(None)
    vision_embedding_hash: Optional[str] = Field(None)
    
    images_processed: int = Field(0)
    note: Optional[str] = Field(None)


# ============================================================================
# Main Pipeline Manifest
# ============================================================================

class PipelineManifest(BaseModel):
    """
    Main manifest object passed through the pipeline.
    
    Each layer:
    1. Reads the manifest
    2. Performs its processing
    3. Updates ONLY its designated result field
    4. Passes the manifest to the next layer
    """
    
    # Identity
    id: str = Field(..., description="Unique manifest ID (UUID)")
    timestamp: str = Field(..., description="ISO 8601 creation timestamp")
    
    # Raw inputs
    text: str = Field(..., description="Original user input text")
    clean_text: Optional[str] = Field(None, description="Normalized/cleaned text")
    external_chunks: List[str] = Field(default_factory=list, description="External data chunks (RAG)")
    
    # Computed data
    hashes: HashInfo = Field(default_factory=HashInfo)
    embeddings: EmbeddingInfo = Field(default_factory=EmbeddingInfo)
    attachments: List[AttachmentInfo] = Field(default_factory=list)
    flags: FlagInfo = Field(default_factory=FlagInfo)
    
    # Layer results (each layer updates only its section)
    layer0_result: Layer0Result = Field(default_factory=Layer0Result)
    input_prep_result: InputPrepResult = Field(default_factory=InputPrepResult)
    image_processing_result: ImageProcessingResult = Field(default_factory=ImageProcessingResult)
    
    # Aggregated scores
    layer0_score: float = Field(0.0, description="Layer 0 suspicion score")
    prep_score: float = Field(0.0, description="Input prep score")
    image_score: float = Field(0.0, description="Image processing score")
    overall_score: float = Field(0.0, description="Combined pipeline score")
    
    # Pipeline metadata
    pipeline_version: str = Field("1.0.0")
    total_processing_time_ms: float = Field(0.0)
    layers_completed: List[str] = Field(default_factory=list)
    
    # Error tracking
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    
    class Config:
        """Pydantic config."""
        validate_assignment = True
        extra = "allow"  # Allow additional fields for extensibility


# ============================================================================
# Factory Functions
# ============================================================================

def create_manifest(
    text: str,
    external_chunks: Optional[List[str]] = None,
    attachments: Optional[List[AttachmentInfo]] = None,
    manifest_id: Optional[str] = None,
) -> PipelineManifest:
    """
    Create a new pipeline manifest.
    
    Args:
        text: User input text
        external_chunks: Optional external data (RAG results)
        attachments: Optional file/image attachments
        manifest_id: Optional custom ID (auto-generated if not provided)
    
    Returns:
        Initialized PipelineManifest ready for pipeline processing
    """
    return PipelineManifest(
        id=manifest_id or str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        text=text,
        external_chunks=external_chunks or [],
        attachments=attachments or [],
    )


def compute_overall_score(manifest: PipelineManifest) -> float:
    """
    Compute overall risk score from layer scores.
    
    Uses weighted combination:
    - Layer 0: 40% (fast heuristics)
    - Input Prep: 30% (unicode/obfuscation)
    - Image Processing: 30% (steganography/metadata)
    """
    weights = {
        "layer0": 0.4,
        "input_prep": 0.3,
        "image": 0.3,
    }
    
    return (
        manifest.layer0_score * weights["layer0"] +
        manifest.prep_score * weights["input_prep"] +
        manifest.image_score * weights["image"]
    )


# ============================================================================
# Legacy Compatibility
# ============================================================================

# Re-export for backward compatibility with existing code
PreparedInput = PipelineManifest  # Alias for gradual migration
