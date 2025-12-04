"""
Contracts package - Shared data structures and interfaces.
"""

from .manifest import (
    ScanStatus,
    LayerResult,
    Layer0Result,
    InputPrepResult,
    ImageProcessingResult,
    AttachmentInfo,
    PipelineFlags,
    EmbeddingData,
    HashData,
    PipelineManifest,
    create_manifest,
    compute_overall_score,
)

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
