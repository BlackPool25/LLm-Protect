"""
Pipeline Manifest - Shared data structures for LLM-Protect pipeline.

This module defines the data structures that flow through the pipeline stages:
- Layer 0 (Heuristics)
- Input Preparation  
- Image Processing
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime


class ScanStatus(Enum):
    """Status of scanning at each layer."""
    CLEAN = "clean"
    FLAGGED = "flagged"
    REJECTED = "rejected"
    ERROR = "error"


@dataclass
class LayerResult:
    """Result from a single layer processing."""
    status: ScanStatus = ScanStatus.CLEAN
    score: float = 0.0
    note: str = ""
    rule_id: Optional[str] = None
    dataset: Optional[str] = None
    severity: int = 0
    audit_token: Optional[str] = None
    processing_time_ms: float = 0.0


@dataclass
class Layer0Result(LayerResult):
    """Layer 0 (Heuristics) specific results."""
    zero_width_found: int = 0
    invisible_chars_found: int = 0
    unicode_obfuscation_detected: bool = False
    has_long_base64: bool = False
    has_system_delimiter: bool = False
    suspicious_score: float = 0.0
    detected_patterns: List[str] = field(default_factory=list)
    hmacs_generated: int = 0


@dataclass
class InputPrepResult(LayerResult):
    """Input Preparation layer specific results."""
    zero_width_found: int = 0
    invisible_chars_found: int = 0
    unicode_obfuscation_detected: bool = False
    has_long_base64: bool = False
    has_system_delimiter: bool = False
    suspicious_score: float = 0.0
    detected_patterns: List[str] = field(default_factory=list)
    original_char_count: int = 0
    normalized_char_count: int = 0
    emoji_count: int = 0
    emoji_descriptions: List[str] = field(default_factory=list)
    hmacs_generated: int = 0


@dataclass
class ImageProcessingResult(LayerResult):
    """Image Processing layer specific results."""
    images_processed: int = 0
    phash: Optional[str] = None
    ocr_text: Optional[str] = None
    ocr_performed: bool = False
    caption: Optional[str] = None
    stego_score: float = 0.0
    stego_detected: bool = False


@dataclass
class AttachmentInfo:
    """Information about an attachment (file/image)."""
    type: str  # "file", "image", "pdf", etc.
    path: str  # File path
    name: str  # File name
    size_bytes: int  # File size
    hash: Optional[str] = None  # File hash
    description: Optional[str] = None  # Description/caption
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional metadata


@dataclass
class PipelineFlags:
    """Feature flags detected during processing."""
    unicode_normalized: bool = False
    zero_width_removed: bool = False
    hmac_verified: bool = False
    has_emojis: bool = False
    emoji_count: int = 0
    steganography_detected: bool = False


@dataclass
class EmbeddingData:
    """Embedding and encoding information."""
    text_embedding_hash: Optional[str] = None
    text_embedding_vector: Optional[List[float]] = None


@dataclass
class HashData:
    """Hashes and signatures."""
    external_chunks_hmacs: List[str] = field(default_factory=list)
    file_hash: Optional[str] = None


@dataclass
class PipelineManifest:
    """
    Complete pipeline processing manifest.
    
    Flows through all pipeline layers, accumulating results.
    """
    
    # Input data
    text: str = ""
    external_chunks: Optional[List[str]] = None
    attachments: Optional[List[AttachmentInfo]] = None
    
    # Processed data
    clean_text: str = ""
    
    # Layer results
    layer0_result: Layer0Result = field(default_factory=Layer0Result)
    input_prep_result: InputPrepResult = field(default_factory=InputPrepResult)
    image_processing_result: ImageProcessingResult = field(default_factory=ImageProcessingResult)
    
    # Scores
    layer0_score: float = 0.0
    prep_score: float = 0.0
    image_score: float = 0.0
    overall_score: float = 0.0
    
    # Metadata
    request_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    layers_completed: List[str] = field(default_factory=list)
    
    # Internal tracking
    flags: PipelineFlags = field(default_factory=PipelineFlags)
    embeddings: EmbeddingData = field(default_factory=EmbeddingData)
    hashes: HashData = field(default_factory=HashData)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    
    # Timing
    total_processing_time_ms: float = 0.0


def create_manifest(
    text: str,
    external_chunks: Optional[List[str]] = None,
    attachments: Optional[List[AttachmentInfo]] = None,
    request_id: Optional[str] = None,
) -> PipelineManifest:
    """
    Create a new pipeline manifest.
    
    Args:
        text: User input text
        external_chunks: Optional external data (RAG)
        attachments: Optional file/image attachments
        request_id: Optional request ID
    
    Returns:
        New PipelineManifest instance
    """
    import uuid
    
    if not request_id:
        request_id = str(uuid.uuid4())
    
    return PipelineManifest(
        text=text,
        external_chunks=external_chunks,
        attachments=attachments,
        request_id=request_id,
        timestamp=datetime.now(),
    )


def compute_overall_score(manifest: PipelineManifest) -> float:
    """
    Compute overall security score from layer scores.
    
    Combines scores from all layers using weighted average:
    - Layer 0 (Heuristics): 40%
    - Input Prep: 35%
    - Image Processing: 25%
    
    Args:
        manifest: Pipeline manifest with layer results
    
    Returns:
        Overall score between 0.0 (clean) and 1.0 (highly suspicious)
    """
    weights = {
        "layer0": 0.40,
        "prep": 0.35,
        "image": 0.25,
    }
    
    # Get layer scores, defaulting to 0 if no processing
    layer0_score = manifest.layer0_score or manifest.layer0_result.score or 0.0
    prep_score = manifest.prep_score or manifest.input_prep_result.score or 0.0
    image_score = manifest.image_score or manifest.image_processing_result.score or 0.0
    
    # Adjust scores for processed status
    if manifest.image_processing_result.status == ScanStatus.CLEAN:
        image_score = max(image_score, manifest.image_processing_result.stego_score or 0.0)
    
    # Compute weighted average
    overall = (
        layer0_score * weights["layer0"] +
        prep_score * weights["prep"] +
        image_score * weights["image"]
    )
    
    # Clamp to [0, 1]
    return min(1.0, max(0.0, overall))


__all__ = [
    "ScanStatus",
    "LayerResult",
    "Layer0Result",
    "InputPrepResult",
    "ImageProcessingResult",
    "AttachmentInfo",
    "PipelineFlags",
    "EmbeddingData",
    "HashData",
    "PipelineManifest",
    "create_manifest",
    "compute_overall_score",
]
