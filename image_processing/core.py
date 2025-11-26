"""
Core Image Processing functions.

This module provides image analysis capabilities:
- Hash calculation (SHA256, perceptual hash)
- EXIF metadata extraction
- OCR text extraction
- Steganography detection (LSB analysis, entropy)
- Vision-based captioning

All functions are designed for:
1. Efficiency (lazy-load models, cache results)
2. Safety (handle corrupt images gracefully)
3. Comprehensive analysis (multiple detection methods)
"""

import hashlib
import io
import math
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import logging

logger = logging.getLogger(__name__)

# ============================================================================
# Lazy-loaded dependencies
# ============================================================================

_pillow = None
_imagehash = None
_pytesseract = None
_piexif = None
_numpy = None


def _get_pillow():
    """Lazy-load PIL."""
    global _pillow
    if _pillow is None:
        try:
            from PIL import Image
            _pillow = Image
        except ImportError:
            _pillow = False
    return _pillow if _pillow else None


def _get_imagehash():
    """Lazy-load imagehash."""
    global _imagehash
    if _imagehash is None:
        try:
            import imagehash
            _imagehash = imagehash
        except ImportError:
            _imagehash = False
    return _imagehash if _imagehash else None


def _get_pytesseract():
    """Lazy-load pytesseract."""
    global _pytesseract
    if _pytesseract is None:
        try:
            import pytesseract
            _pytesseract = pytesseract
        except ImportError:
            _pytesseract = False
    return _pytesseract if _pytesseract else None


def _get_piexif():
    """Lazy-load piexif."""
    global _piexif
    if _piexif is None:
        try:
            import piexif
            _piexif = piexif
        except ImportError:
            _piexif = False
    return _piexif if _piexif else None


def _get_numpy():
    """Lazy-load numpy."""
    global _numpy
    if _numpy is None:
        try:
            import numpy as np
            _numpy = np
        except ImportError:
            _numpy = False
    return _numpy if _numpy else None


# ============================================================================
# Hash Calculation
# ============================================================================

def calculate_hash(image_path: str) -> Optional[str]:
    """
    Calculate SHA256 hash of image file.
    
    Args:
        image_path: Path to image file
    
    Returns:
        SHA256 hex digest or None if failed
    """
    try:
        with open(image_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        logger.error(f"Hash calculation failed: {e}")
        return None


def calculate_hash_from_bytes(image_bytes: bytes) -> str:
    """Calculate SHA256 hash from image bytes."""
    return hashlib.sha256(image_bytes).hexdigest()


@lru_cache(maxsize=500)
def calculate_phash(image_path: str) -> Optional[str]:
    """
    Calculate perceptual hash (pHash) of image.
    
    pHash is robust to resizing and minor modifications,
    useful for finding similar images.
    
    Args:
        image_path: Path to image file
    
    Returns:
        pHash as hex string or None if unavailable
    """
    Image = _get_pillow()
    imagehash = _get_imagehash()
    
    if not Image or not imagehash:
        return None
    
    try:
        with Image.open(image_path) as img:
            phash = imagehash.phash(img)
            return str(phash)
    except Exception as e:
        logger.error(f"pHash calculation failed: {e}")
        return None


def calculate_phash_from_bytes(image_bytes: bytes) -> Optional[str]:
    """Calculate pHash from image bytes."""
    Image = _get_pillow()
    imagehash = _get_imagehash()
    
    if not Image or not imagehash:
        return None
    
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            phash = imagehash.phash(img)
            return str(phash)
    except Exception as e:
        logger.error(f"pHash from bytes failed: {e}")
        return None


# ============================================================================
# EXIF Extraction
# ============================================================================

def extract_exif(image_path: str) -> Dict[str, Any]:
    """
    Extract EXIF metadata from image.
    
    Args:
        image_path: Path to image file
    
    Returns:
        Dictionary of EXIF data
    """
    result = {
        "extracted": False,
        "data": {},
        "suspicious": False,
        "embedded_text": None,
    }
    
    piexif = _get_piexif()
    if not piexif:
        return result
    
    try:
        exif_dict = piexif.load(image_path)
        result["extracted"] = True
        
        # Process each IFD
        for ifd_name in ["0th", "Exif", "GPS", "1st"]:
            if ifd_name not in exif_dict:
                continue
            
            ifd = exif_dict[ifd_name]
            for tag, value in ifd.items():
                try:
                    tag_info = piexif.TAGS.get(ifd_name, {}).get(tag, {})
                    tag_name = tag_info.get("name", f"Unknown_{tag}")
                    
                    # Convert bytes to string
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="ignore").strip("\x00")
                        except:
                            value = str(value)
                    
                    result["data"][tag_name] = value
                    
                    # Check for suspicious content
                    if tag_name in ("UserComment", "ImageDescription", "XPComment"):
                        text = str(value).lower()
                        if any(kw in text for kw in ["script", "exec", "eval", "system"]):
                            result["suspicious"] = True
                        if len(str(value)) > 10:
                            result["embedded_text"] = str(value)
                            
                except Exception:
                    continue
        
    except Exception as e:
        logger.debug(f"EXIF extraction failed (may be normal): {e}")
    
    return result


# ============================================================================
# OCR
# ============================================================================

def perform_ocr(image_path: str, lang: str = "eng") -> Dict[str, Any]:
    """
    Perform OCR on image to extract text.
    
    Args:
        image_path: Path to image file
        lang: Tesseract language code
    
    Returns:
        Dictionary with OCR results
    """
    result = {
        "performed": False,
        "text": None,
        "confidence": None,
    }
    
    Image = _get_pillow()
    pytesseract = _get_pytesseract()
    
    if not Image or not pytesseract:
        return result
    
    try:
        with Image.open(image_path) as img:
            # Get detailed OCR data
            data = pytesseract.image_to_data(img, lang=lang, output_type=pytesseract.Output.DICT)
            
            # Extract text
            text_parts = []
            confidences = []
            
            for i, word in enumerate(data["text"]):
                if word.strip():
                    text_parts.append(word)
                    conf = data["conf"][i]
                    if isinstance(conf, (int, float)) and conf >= 0:
                        confidences.append(conf)
            
            result["performed"] = True
            result["text"] = " ".join(text_parts) if text_parts else None
            result["confidence"] = sum(confidences) / len(confidences) if confidences else 0.0
            
    except Exception as e:
        logger.warning(f"OCR failed: {e}")
    
    return result


# ============================================================================
# Steganography Detection
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    High entropy (> 7.5 for random data) may indicate hidden content.
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # Calculate entropy
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy


def detect_steganography(image_path: str) -> Dict[str, Any]:
    """
    Detect potential steganography in image.
    
    Uses multiple detection methods:
    1. LSB (Least Significant Bit) analysis
    2. Entropy analysis
    3. Chi-square test on color channels
    
    Args:
        image_path: Path to image file
    
    Returns:
        Dictionary with steganography analysis results
    """
    result = {
        "stego_score": 0.0,
        "detected": False,
        "entropy": None,
        "entropy_suspicious": False,
        "lsb_anomaly": False,
        "chi_square_scores": [],
        "analysis_notes": [],
    }
    
    Image = _get_pillow()
    np = _get_numpy()
    
    if not Image or not np:
        result["analysis_notes"].append("Required libraries not available")
        return result
    
    try:
        with Image.open(image_path) as img:
            # Convert to RGB if necessary
            if img.mode != "RGB":
                img = img.convert("RGB")
            
            # Get image data
            pixels = np.array(img)
            
            # 1. File entropy analysis
            with open(image_path, "rb") as f:
                file_data = f.read()
            
            file_entropy = calculate_entropy(file_data)
            result["entropy"] = file_entropy
            
            # Random data has entropy ~8, images typically 6-7.5
            if file_entropy > 7.8:
                result["entropy_suspicious"] = True
                result["stego_score"] += 0.3
                result["analysis_notes"].append("High file entropy")
            
            # 2. LSB analysis per channel
            for channel_idx, channel_name in enumerate(["R", "G", "B"]):
                channel = pixels[:, :, channel_idx].flatten()
                
                # Extract LSBs
                lsbs = channel & 1
                
                # Chi-square test: expect 50% 0s, 50% 1s in random LSBs
                ones = np.sum(lsbs)
                zeros = len(lsbs) - ones
                expected = len(lsbs) / 2
                
                chi_square = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
                result["chi_square_scores"].append(float(chi_square))
                
                # Very low chi-square suggests artificial randomization
                if chi_square < 1.0:
                    result["lsb_anomaly"] = True
                    result["stego_score"] += 0.2
                    result["analysis_notes"].append(f"{channel_name} channel LSB too uniform")
            
            # 3. Check for appended data
            img_size = pixels.nbytes
            file_size = os.path.getsize(image_path)
            overhead_ratio = file_size / max(img_size, 1)
            
            if overhead_ratio > 2.0:  # More than 2x expected size
                result["stego_score"] += 0.2
                result["analysis_notes"].append("Unusually large file size")
            
            # 4. Normalize score
            result["stego_score"] = min(result["stego_score"], 1.0)
            result["detected"] = result["stego_score"] > 0.5
            
    except Exception as e:
        logger.error(f"Steganography detection failed: {e}")
        result["analysis_notes"].append(f"Analysis error: {e}")
    
    return result


# ============================================================================
# Vision Captioning (placeholder for actual model)
# ============================================================================

def generate_caption(image_path: str) -> Optional[str]:
    """
    Generate caption for image using vision model.
    
    Note: This is a placeholder. In production, integrate with:
    - BLIP/BLIP-2
    - LLaVA
    - Claude Vision
    - GPT-4V
    
    Args:
        image_path: Path to image file
    
    Returns:
        Generated caption or None
    """
    # Placeholder - integrate actual vision model here
    Image = _get_pillow()
    if not Image:
        return None
    
    try:
        with Image.open(image_path) as img:
            width, height = img.size
            format_name = img.format or "unknown"
            mode = img.mode
            
            return f"Image ({format_name}, {width}x{height}, {mode})"
    except Exception as e:
        logger.error(f"Caption generation failed: {e}")
        return None


# ============================================================================
# Unified Analysis Function
# ============================================================================

def analyze_image(
    image_path: str,
    include_ocr: bool = True,
    include_stego: bool = True,
) -> Dict[str, Any]:
    """
    Perform comprehensive image analysis.
    
    Args:
        image_path: Path to image file
        include_ocr: Whether to perform OCR
        include_stego: Whether to run steganography detection
    
    Returns:
        Comprehensive analysis results
    """
    result = {
        "hash": None,
        "phash": None,
        "format": None,
        "dimensions": None,
        "size_bytes": None,
        "exif": {},
        "exif_suspicious": False,
        "embedded_text": None,
        "ocr_text": None,
        "ocr_confidence": None,
        "stego_score": 0.0,
        "stego_detected": False,
        "entropy": None,
        "caption": None,
        "error": None,
    }
    
    Image = _get_pillow()
    
    if not os.path.exists(image_path):
        result["error"] = "File not found"
        return result
    
    try:
        # Basic file info
        result["hash"] = calculate_hash(image_path)
        result["size_bytes"] = os.path.getsize(image_path)
        
        # Image properties
        if Image:
            with Image.open(image_path) as img:
                result["format"] = img.format
                result["dimensions"] = img.size
        
        # pHash
        result["phash"] = calculate_phash(image_path)
        
        # EXIF
        exif_result = extract_exif(image_path)
        result["exif"] = exif_result["data"]
        result["exif_suspicious"] = exif_result["suspicious"]
        result["embedded_text"] = exif_result["embedded_text"]
        
        # OCR
        if include_ocr:
            ocr_result = perform_ocr(image_path)
            result["ocr_text"] = ocr_result["text"]
            result["ocr_confidence"] = ocr_result["confidence"]
        
        # Steganography
        if include_stego:
            stego_result = detect_steganography(image_path)
            result["stego_score"] = stego_result["stego_score"]
            result["stego_detected"] = stego_result["detected"]
            result["entropy"] = stego_result["entropy"]
        
        # Caption
        result["caption"] = generate_caption(image_path)
        
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Image analysis failed: {e}")
    
    return result


# ============================================================================
# Pipeline Run Function
# ============================================================================

def run(manifest: "PipelineManifest") -> "PipelineManifest":
    """
    Run image processing on a manifest.
    
    This is the main entry point for the image_processing layer.
    
    Args:
        manifest: Pipeline manifest to process
    
    Returns:
        Updated manifest with image_processing_result populated
    """
    from contracts.manifest import ScanStatus
    import time
    
    start = time.perf_counter()
    
    if not manifest.attachments:
        manifest.image_processing_result.status = ScanStatus.CLEAN
        manifest.image_processing_result.note = "No attachments to process"
        manifest.image_processing_result.processing_time_ms = (time.perf_counter() - start) * 1000
        return manifest
    
    try:
        images_processed = 0
        max_stego_score = 0.0
        
        for attachment in manifest.attachments:
            if attachment.type != "image":
                continue
            
            image_path = attachment.metadata.get("path")
            if not image_path or not os.path.exists(image_path):
                continue
            
            # Analyze image
            result = analyze_image(image_path)
            images_processed += 1
            
            # Update attachment
            attachment.hash = result["hash"]
            attachment.format = result["format"]
            attachment.dimensions = result["dimensions"]
            attachment.description = result["caption"]
            attachment.metadata["phash"] = result["phash"]
            attachment.metadata["stego_score"] = result["stego_score"]
            attachment.metadata["exif"] = result["exif"]
            attachment.metadata["ocr_text"] = result["ocr_text"]
            
            # Update hash info
            if result["phash"]:
                manifest.hashes.image_phash = result["phash"]
            if result["hash"]:
                manifest.hashes.image_sha256 = result["hash"]
            
            # Track max stego score
            max_stego_score = max(max_stego_score, result["stego_score"])
            
            # Update result fields
            if result["phash"]:
                manifest.image_processing_result.phash = result["phash"]
            if result["ocr_text"]:
                manifest.image_processing_result.ocr_text = result["ocr_text"]
                manifest.image_processing_result.ocr_performed = True
                manifest.image_processing_result.ocr_confidence = result["ocr_confidence"]
            if result["caption"]:
                manifest.image_processing_result.caption = result["caption"]
            if result["format"]:
                manifest.image_processing_result.format = result["format"]
            if result["dimensions"]:
                manifest.image_processing_result.dimensions = result["dimensions"]
            if result["size_bytes"]:
                manifest.image_processing_result.size_bytes = result["size_bytes"]
            if result["entropy"]:
                manifest.image_processing_result.entropy = result["entropy"]
                manifest.image_processing_result.entropy_suspicious = result.get("entropy", 0) > 7.8
            
            manifest.image_processing_result.exif_extracted = bool(result["exif"])
            manifest.image_processing_result.exif_suspicious = result["exif_suspicious"]
            if result["embedded_text"]:
                manifest.image_processing_result.embedded_text_from_exif = result["embedded_text"]
        
        # Final updates
        manifest.image_processing_result.images_processed = images_processed
        manifest.image_processing_result.stego_score = max_stego_score
        manifest.image_processing_result.stego_detected = max_stego_score > 0.5
        manifest.image_processing_result.score = max_stego_score
        manifest.image_score = max_stego_score
        
        # Update flags
        manifest.flags.steganography_detected = max_stego_score > 0.5
        manifest.flags.suspicious_metadata = any(
            a.metadata.get("exif_suspicious", False) 
            for a in manifest.attachments if a.type == "image"
        )
        manifest.flags.ocr_performed = manifest.image_processing_result.ocr_performed
        manifest.flags.high_entropy = manifest.image_processing_result.entropy_suspicious
        
        # Set status
        if max_stego_score > 0.7:
            manifest.image_processing_result.status = ScanStatus.WARN
            manifest.image_processing_result.note = "High steganography score"
        elif manifest.image_processing_result.exif_suspicious:
            manifest.image_processing_result.status = ScanStatus.WARN
            manifest.image_processing_result.note = "Suspicious EXIF metadata"
        else:
            manifest.image_processing_result.status = ScanStatus.CLEAN
        
    except Exception as e:
        manifest.image_processing_result.status = ScanStatus.ERROR
        manifest.image_processing_result.note = str(e)
        logger.error(f"Image processing error: {e}")
    
    manifest.image_processing_result.processing_time_ms = (time.perf_counter() - start) * 1000
    
    return manifest
