"""
Image Processing module.

Handles image analysis for the LLM-Protect pipeline:
- Hash calculation (SHA256, pHash)
- EXIF metadata extraction
- OCR text extraction
- Steganography detection
- Vision captioning
"""

from image_processing.core import (
    analyze_image,
    calculate_hash,
    calculate_phash,
    extract_exif,
    detect_steganography,
    perform_ocr,
    generate_caption,
    run as run_image_processing,
)

__all__ = [
    "analyze_image",
    "calculate_hash",
    "calculate_phash",
    "extract_exif",
    "detect_steganography",
    "perform_ocr",
    "generate_caption",
    "run_image_processing",
]
