"""
Feature fusion layer for the Security Guard System.

This module combines features from image and emoji/text pipelines into
a unified feature representation for anomaly detection.
"""

import hashlib
import numpy as np
from typing import Optional, Dict, List

from security.core.types import (
    IncomingRequest,
    ImageFeaturePack,
    EmojiFeaturePack,
    FusionFeatures,
    FusionMetadata,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# Feature Normalization
# ============================================================================

def normalize_features(features: Dict[str, float]) -> np.ndarray:
    """
    Normalize numeric features to 0-1 range.
    
    Args:
        features: Dictionary of feature name -> value
        
    Returns:
        Numpy array of normalized values
    """
    # Features are already mostly in 0-1 range from pipelines
    # This function ensures consistency and handles any outliers
    values = []
    for key, value in features.items():
        # Clip to 0-1 range
        normalized = np.clip(value, 0.0, 1.0)
        values.append(normalized)
    
    return np.array(values, dtype=np.float32)


# ============================================================================
# Feature Vector Concatenation
# ============================================================================

def concatenate_feature_vectors(
    image_pack: Optional[ImageFeaturePack],
    emoji_pack: Optional[EmojiFeaturePack]
) -> np.ndarray:
    """
    Concatenate all numeric features into a single vector.
    
    Handles missing modalities gracefully by filling with zeros.
    
    Args:
        image_pack: Image features (optional)
        emoji_pack: Emoji/text features (optional)
        
    Returns:
        Concatenated feature vector
    """
    feature_list = []
    
    # === Image Features ===
    if image_pack:
        # Stego score (1 feature)
        feature_list.append(image_pack.stego_score)
        
        # Image embedding (128 features)
        feature_list.extend(image_pack.image_embedding)
        
        # Image stats (3 features)
        feature_list.append(image_pack.image_stats.mean_brightness / 255.0)  # Normalize to 0-1
        feature_list.append(min(image_pack.image_stats.aspect_ratio, 10.0) / 10.0)  # Normalize aspect ratio
        feature_list.append(image_pack.image_stats.channels / 4.0)  # Normalize channels (max 4)
    else:
        # Fill with zeros if no image (1 + 128 + 3 = 132 features)
        feature_list.extend([0.0] * 132)
    
    # === Emoji Features ===
    if emoji_pack:
        # Emoji risk score (1 feature)
        feature_list.append(emoji_pack.emoji_risk_score)
        
        # Pattern features (4 features)
        feature_list.append(emoji_pack.pattern_features.repetition_score)
        feature_list.append(1.0 if emoji_pack.pattern_features.cipher_like else 0.0)
        feature_list.append(1.0 if emoji_pack.pattern_features.mixed_script_with_emoji else 0.0)
        feature_list.append(emoji_pack.pattern_features.pattern_complexity)
        
        # Unicode threat features (4 features)
        feature_list.append(1.0 if emoji_pack.unicode_threats.has_zero_width else 0.0)
        feature_list.append(1.0 if emoji_pack.unicode_threats.has_bidi_override else 0.0)
        feature_list.append(1.0 if emoji_pack.unicode_threats.has_homoglyphs else 0.0)
        feature_list.append(emoji_pack.unicode_threats.overall_unicode_threat_score)
        
        # Threat counts (normalized, 3 features)
        feature_list.append(min(emoji_pack.unicode_threats.zero_width_count / 10.0, 1.0))
        feature_list.append(min(emoji_pack.unicode_threats.bidi_override_count / 10.0, 1.0))
        feature_list.append(min(emoji_pack.unicode_threats.homoglyph_count / 10.0, 1.0))
    else:
        # Fill with zeros if no emoji/text (1 + 4 + 4 + 3 = 12 features)
        feature_list.extend([0.0] * 12)
    
    # Convert to numpy array
    feature_vector = np.array(feature_list, dtype=np.float32)
    
    logger.debug(f"Concatenated feature vector: {feature_vector.shape[0]} features")
    return feature_vector


# ============================================================================
# Metadata Generation
# ============================================================================

def generate_fusion_metadata(
    request: IncomingRequest,
    image_pack: Optional[ImageFeaturePack],
    emoji_pack: Optional[EmojiFeaturePack]
) -> FusionMetadata:
    """
    Generate metadata about the fusion process.
    
    Args:
        request: Original incoming request
        image_pack: Image features (if present)
        emoji_pack: Emoji features (if present)
        
    Returns:
        FusionMetadata object
    """
    has_image = image_pack is not None
    has_emojis = emoji_pack is not None and len(emoji_pack.emoji_sequence) > 0
    text_length = len(request.text) if request.text else 0
    
    # Generate combined hash
    hash_input = ""
    if image_pack:
        hash_input += image_pack.hash
    if request.text:
        hash_input += request.text
    
    combined_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    
    return FusionMetadata(
        has_image=has_image,
        has_emojis=has_emojis,
        text_length=text_length,
        hash=combined_hash
    )


# ============================================================================
# Main Fusion Function
# ============================================================================

def build_fusion_features(
    request: IncomingRequest,
    image_pack: Optional[ImageFeaturePack] = None,
    emoji_pack: Optional[EmojiFeaturePack] = None
) -> FusionFeatures:
    """
    Build fused features from all pipelines.
    
    Combines image and emoji/text features into a unified representation.
    Handles missing modalities gracefully.
    
    Args:
        request: Original incoming request
        image_pack: Image feature pack (optional)
        emoji_pack: Emoji feature pack (optional)
        
    Returns:
        FusionFeatures with combined feature vector and metadata
        
    Example:
        >>> fusion = build_fusion_features(request, image_pack, emoji_pack)
        >>> fusion.vector.shape
        (144,)  # 132 image + 12 emoji features
        >>> fusion.metadata.has_image
        True
    """
    # Concatenate feature vectors
    feature_vector = concatenate_feature_vectors(image_pack, emoji_pack)
    
    # Generate metadata
    metadata = generate_fusion_metadata(request, image_pack, emoji_pack)
    
    # Create fusion features object
    fusion_features = FusionFeatures(
        vector=feature_vector.tolist(),
        image_features=image_pack,
        emoji_features=emoji_pack,
        metadata=metadata
    )
    
    logger.info(
        f"Fusion features built: vector_dim={len(feature_vector)}, "
        f"has_image={metadata.has_image}, has_emojis={metadata.has_emojis}"
    )
    
    return fusion_features


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "normalize_features",
    "concatenate_feature_vectors",
    "generate_fusion_metadata",
    "build_fusion_features",
]
