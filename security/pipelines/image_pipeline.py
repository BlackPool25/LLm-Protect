"""
Image processing pipeline for the Security Guard System.

This module orchestrates all image-related security checks including:
- Image sanity validation (MIME, size, format)
- Image preprocessing (downscaling, RGB conversion)
- Steganography detection
- Image embedding generation (stub or ONNX model)
- Feature pack assembly
"""

import io
import hashlib
import numpy as np
from typing import Tuple, Optional
from PIL import Image

from security.core.types import (
    ImageSanityCheck,
    StegoFeature,
    ImageStats,
    ImageFeaturePack,
)
from security.detectors.steganography import SteganographyDetector
from config.security_config import (
    IMAGE_TARGET_SIZE,
    IMAGE_EMBEDDING_DIM,
    MAX_IMAGE_SIZE_MB,
    SUPPORTED_IMAGE_FORMATS,
    MAX_IMAGE_WIDTH,
    MAX_IMAGE_HEIGHT,
    MIN_IMAGE_WIDTH,
    MIN_IMAGE_HEIGHT,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# Image Sanity Check
# ============================================================================

def validate_image_sanity(image_bytes: bytes) -> ImageSanityCheck:
    """
    Validate image format, size, and dimensions.
    
    Args:
        image_bytes: Raw image data
        
    Returns:
        ImageSanityCheck with validation results
        
    Example:
        >>> result = validate_image_sanity(image_data)
        >>> if not result.is_valid:
        >>>     print(f"Invalid image: {result.error}")
    """
    try:
        # Check file size
        size_bytes = len(image_bytes)
        max_bytes = MAX_IMAGE_SIZE_MB * 1024 * 1024
        
        if size_bytes > max_bytes:
            return ImageSanityCheck(
                is_valid=False,
                size_bytes=size_bytes,
                error=f"Image size ({size_bytes} bytes) exceeds maximum ({max_bytes} bytes)"
            )
        
        # Open image and validate
        img = Image.open(io.BytesIO(image_bytes))
        width, height = img.size
        img_format = img.format
        
        # Validate format
        if img_format not in SUPPORTED_IMAGE_FORMATS:
            return ImageSanityCheck(
                is_valid=False,
                width=width,
                height=height,
                format=img_format,
                size_bytes=size_bytes,
                error=f"Unsupported image format: {img_format}"
            )
        
        # Validate dimensions
        if width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT:
            return ImageSanityCheck(
                is_valid=False,
                width=width,
                height=height,
                format=img_format,
                size_bytes=size_bytes,
                error=f"Image dimensions ({width}x{height}) exceed maximum ({MAX_IMAGE_WIDTH}x{MAX_IMAGE_HEIGHT})"
            )
        
        if width < MIN_IMAGE_WIDTH or height < MIN_IMAGE_HEIGHT:
            return ImageSanityCheck(
                is_valid=False,
                width=width,
                height=height,
                format=img_format,
                size_bytes=size_bytes,
                error=f"Image dimensions ({width}x{height}) below minimum ({MIN_IMAGE_WIDTH}x{MIN_IMAGE_HEIGHT})"
            )
        
        # Detect MIME type
        mime_type = f"image/{img_format.lower()}"
        
        return ImageSanityCheck(
            is_valid=True,
            mime_type=mime_type,
            width=width,
            height=height,
            size_bytes=size_bytes,
            format=img_format,
            error=None
        )
        
    except Exception as e:
        logger.error(f"Image sanity check failed: {e}")
        return ImageSanityCheck(
            is_valid=False,
            error=f"Failed to process image: {str(e)}"
        )


# ============================================================================
# Image Preprocessing
# ============================================================================

def preprocess_image(
    image_bytes: bytes,
    target_size: Tuple[int, int] = IMAGE_TARGET_SIZE
) -> np.ndarray:
    """
    Preprocess image for analysis.
    
    - Downscale to target size
    - Convert to RGB
    - Return as numpy array
    
    Args:
        image_bytes: Raw image data
        target_size: Target dimensions (width, height)
        
    Returns:
        Numpy array of shape (height, width, 3) with RGB values
        
    Raises:
        ValueError: If image cannot be processed
    """
    try:
        img = Image.open(io.BytesIO(image_bytes))
        
        # Convert to RGB (handles RGBA, grayscale, etc.)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Resize to target size
        img = img.resize(target_size, Image.Resampling.LANCZOS)
        
        # Convert to numpy array
        img_array = np.array(img, dtype=np.float32)
        
        logger.debug(f"Preprocessed image to shape: {img_array.shape}")
        return img_array
        
    except Exception as e:
        logger.error(f"Image preprocessing failed: {e}")
        raise ValueError(f"Failed to preprocess image: {str(e)}")


# ============================================================================
# Steganography Feature Extraction
# ============================================================================

async def compute_stego_features(image_bytes: bytes) -> StegoFeature:
    """
    Compute steganography features using existing detector.
    
    Args:
        image_bytes: Raw image data
        
    Returns:
        StegoFeature object with analysis results
    """
    try:
        detector = SteganographyDetector()
        result = await detector.analyze(image_bytes)
        
        # Extract relevant features
        # LSBAnalysis has: chi_square_scores, entropy_scores, correlation_scores, anomaly_detected, confidence
        lsb_stats = {}
        if result.lsb_analysis:
            lsb_stats = {
                "confidence": result.lsb_analysis.confidence,
                "anomaly_detected": result.lsb_analysis.anomaly_detected,
                "avg_chi_square": sum(result.lsb_analysis.chi_square_scores) / len(result.lsb_analysis.chi_square_scores) if result.lsb_analysis.chi_square_scores else 0.0,
                "avg_entropy": sum(result.lsb_analysis.entropy_scores) / len(result.lsb_analysis.entropy_scores) if result.lsb_analysis.entropy_scores else 0.0,
            }
        
        stego_feature = StegoFeature(
            stego_score=result.overall_stego_score,
            lsb_stats=lsb_stats,
            chi_square=lsb_stats.get("avg_chi_square"),
            bit_plane_entropy=lsb_stats.get("avg_entropy"),
            noise_profile_score=result.noise_profile_score if hasattr(result, 'noise_profile_score') else 0.0,
            correlation_score=result.color_correlation_score if hasattr(result, 'color_correlation_score') else 0.0,
        )
        
        logger.debug(f"Stego score: {stego_feature.stego_score:.3f}")
        return stego_feature
        
    except Exception as e:
        logger.error(f"Steganography analysis failed: {e}")
        # Return safe default on error
        return StegoFeature(
            stego_score=0.0,
            lsb_stats={},
            chi_square=None,
            bit_plane_entropy=None,
            noise_profile_score=None,
            correlation_score=None,
        )


# ============================================================================
# Image Embedding (Stub Implementation)
# ============================================================================

def get_image_embedding(image_array: np.ndarray) -> Tuple[np.ndarray, bool]:
    """
    Generate image embedding vector.
    
    Currently uses a stub implementation that generates a deterministic
    vector based on image hash. This can be replaced with an actual
    ONNX model (e.g., MobileNetV3-Small) in the future.
    
    Args:
        image_array: Preprocessed image as numpy array
        
    Returns:
        Tuple of (embedding_vector, is_stub)
        - embedding_vector: 128-dimensional float array
        - is_stub: True (indicating this is a stub implementation)
    """
    try:
        # Generate deterministic hash-based embedding
        # This ensures same image always gets same embedding
        image_hash = hashlib.sha256(image_array.tobytes()).digest()
        
        # Convert hash to 128 floats in range [0, 1]
        # Use multiple hash iterations to get enough bytes
        embedding = []
        for i in range(IMAGE_EMBEDDING_DIM // 32):
            hash_input = image_hash + i.to_bytes(4, 'big')
            hash_output = hashlib.sha256(hash_input).digest()
            # Convert bytes to floats
            for j in range(0, 32, 1):
                if len(embedding) < IMAGE_EMBEDDING_DIM:
                    embedding.append(hash_output[j] / 255.0)
        
        embedding_array = np.array(embedding[:IMAGE_EMBEDDING_DIM], dtype=np.float32)
        
        logger.debug(f"Generated stub embedding: {embedding_array.shape}")
        return embedding_array, True  # is_stub=True
        
    except Exception as e:
        logger.error(f"Embedding generation failed: {e}")
        # Return zero vector on error
        return np.zeros(IMAGE_EMBEDDING_DIM, dtype=np.float32), True


# ============================================================================
# Image Statistics
# ============================================================================

def compute_image_stats(image_array: np.ndarray) -> ImageStats:
    """
    Compute basic image statistics.
    
    Args:
        image_array: Image as numpy array (H, W, C)
        
    Returns:
        ImageStats object
    """
    height, width, channels = image_array.shape
    
    # Compute mean brightness (average across all channels)
    mean_brightness = float(np.mean(image_array))
    
    # Compute aspect ratio
    aspect_ratio = width / height if height > 0 else 1.0
    
    return ImageStats(
        width=width,
        height=height,
        aspect_ratio=aspect_ratio,
        mean_brightness=mean_brightness,
        channels=channels
    )


# ============================================================================
# Main Pipeline Function
# ============================================================================

async def build_image_feature_pack(image_bytes: bytes) -> ImageFeaturePack:
    """
    Build complete image feature pack.
    
    Orchestrates all image pipeline steps:
    1. Validate image sanity
    2. Preprocess image
    3. Compute steganography features
    4. Generate image embedding
    5. Compute image statistics
    6. Assemble feature pack
    
    Args:
        image_bytes: Raw image data
        
    Returns:
        ImageFeaturePack with all features
        
    Raises:
        ValueError: If image fails sanity check or preprocessing
    """
    # Step 1: Validate image
    sanity_check = validate_image_sanity(image_bytes)
    if not sanity_check.is_valid:
        raise ValueError(f"Image validation failed: {sanity_check.error}")
    
    # Step 2: Preprocess image
    image_array = preprocess_image(image_bytes)
    
    # Step 3: Compute steganography features (async)
    stego_feature = await compute_stego_features(image_bytes)
    
    # Step 4: Generate embedding
    embedding, is_stub = get_image_embedding(image_array)
    
    # Step 5: Compute statistics
    image_stats = compute_image_stats(image_array)
    
    # Step 6: Compute hash
    image_hash = hashlib.sha256(image_bytes).hexdigest()
    
    # Assemble feature pack
    feature_pack = ImageFeaturePack(
        stego_score=stego_feature.stego_score,
        image_embedding=embedding.tolist(),
        image_stats=image_stats,
        hash=image_hash,
        embedding_is_stub=is_stub
    )
    
    logger.info(f"Image feature pack built: stego_score={feature_pack.stego_score:.3f}, hash={image_hash[:16]}...")
    return feature_pack


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "validate_image_sanity",
    "preprocess_image",
    "compute_stego_features",
    "get_image_embedding",
    "compute_image_stats",
    "build_image_feature_pack",
]
