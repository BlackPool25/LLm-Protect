"""
Contracts module for LLM-Protect pipeline.

Defines shared data structures used across all layers:
- Layer 0 (Heuristics/Regex)
- Input Preparation
- Image Processing

Also provides shared utilities to eliminate redundancy.
"""

from contracts.manifest import (
    PipelineManifest,
    HashInfo,
    EmbeddingInfo,
    AttachmentInfo,
    FlagInfo,
    Layer0Result,
    InputPrepResult,
    ImageProcessingResult,
    ScanStatus,
    Severity,
    create_manifest,
    compute_overall_score,
)

from contracts.shared import (
    ModelManager,
    HMACManager,
    hash_sha256,
    hash_file_sha256,
    hash_string_sha256,
    generate_embedding_hash,
    generate_embedding_with_vector,
    clear_embedding_cache,
    normalize_text,
    analyze_unicode,
)

__all__ = [
    # Manifest types
    "PipelineManifest",
    "HashInfo",
    "EmbeddingInfo",
    "AttachmentInfo",
    "FlagInfo",
    "Layer0Result",
    "InputPrepResult",
    "ImageProcessingResult",
    "ScanStatus",
    "Severity",
    "create_manifest",
    "compute_overall_score",
    # Shared utilities
    "ModelManager",
    "HMACManager",
    "hash_sha256",
    "hash_file_sha256",
    "hash_string_sha256",
    "generate_embedding_hash",
    "generate_embedding_with_vector",
    "clear_embedding_cache",
    "normalize_text",
    "analyze_unicode",
]
