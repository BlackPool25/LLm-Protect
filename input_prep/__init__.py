"""
Input Preparation module.

Handles text normalization, HMAC verification, embedding generation,
and stub extraction for the LLM-Protect pipeline.
"""

from input_prep.core import (
    normalize_text,
    analyze_unicode,
    run_heuristics,
    generate_embedding,
    generate_hmacs,
    extract_emojis,
    run as run_input_prep,
)

__all__ = [
    "normalize_text",
    "analyze_unicode",
    "run_heuristics",
    "generate_embedding",
    "generate_hmacs",
    "extract_emojis",
    "run_input_prep",
]
