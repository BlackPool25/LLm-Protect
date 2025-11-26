"""
Core Input Preparation functions.

This module provides the core functions for input preparation:
- Text normalization (Unicode, whitespace, homoglyphs)
- Unicode obfuscation detection
- Fast heuristic checks
- Text embedding generation
- HMAC signing for external chunks
- Emoji extraction and description

All functions are designed to be:
1. Fast (minimize latency)
2. Stateless (no side effects)
3. Cacheable (deterministic outputs)
"""

import hashlib
import hmac
import re
import unicodedata
from functools import lru_cache
from typing import Dict, List, Optional, Any, Tuple

# ============================================================================
# Lazy-loaded dependencies
# ============================================================================

_embedding_model = None
_emoji_lib = None


def _get_embedding_model():
    """Lazy-load sentence transformer model."""
    global _embedding_model
    if _embedding_model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        except ImportError:
            _embedding_model = False  # Mark as unavailable
    return _embedding_model if _embedding_model else None


def _get_emoji_lib():
    """Lazy-load emoji library."""
    global _emoji_lib
    if _emoji_lib is None:
        try:
            import emoji
            _emoji_lib = emoji
        except ImportError:
            _emoji_lib = False
    return _emoji_lib if _emoji_lib else None


# ============================================================================
# Constants
# ============================================================================

# Zero-width and invisible characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE
    "\u2060",  # WORD JOINER
    "\u180e",  # MONGOLIAN VOWEL SEPARATOR
}

# Bidirectional control characters
BIDI_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}

# Common homoglyphs (Cyrillic/Greek -> ASCII)
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "α": "a", "β": "b", "ο": "o", "ρ": "r",
}

# Suspicious patterns for heuristics
SUSPICIOUS_PATTERNS = [
    (r"(?:system|assistant|user)\s*:", "system_delimiter"),
    (r"ignore\s+(?:previous|above|all)", "ignore_instruction"),
    (r"disregard\s+(?:previous|above|all)", "disregard_instruction"),
    (r"pretend\s+(?:you\s+are|to\s+be)", "pretend_instruction"),
    (r"act\s+as\s+(?:if|a)", "act_as_instruction"),
    (r"<!--.*?-->", "html_comment"),
    (r"</?(?:system|prompt|instruction)[^>]*>", "xml_injection"),
    (r"[A-Za-z0-9+/]{100,}={0,2}", "long_base64"),
]

# Compile patterns once
_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), name) for p, name in SUSPICIOUS_PATTERNS]


# ============================================================================
# Text Normalization
# ============================================================================

def normalize_text(text: str) -> str:
    """
    Normalize text for security analysis.
    
    Steps:
    1. Unicode NFKC normalization
    2. Zero-width character removal
    3. Bidi control removal
    4. Homoglyph replacement
    5. Whitespace normalization
    
    Args:
        text: Raw input text
    
    Returns:
        Normalized text
    """
    if not text:
        return ""
    
    # Step 1: Unicode NFKC normalization
    text = unicodedata.normalize("NFKC", text)
    
    # Step 2: Remove zero-width characters
    for char in ZERO_WIDTH_CHARS:
        text = text.replace(char, "")
    
    # Step 3: Remove bidi control characters
    for char in BIDI_CHARS:
        text = text.replace(char, "")
    
    # Step 4: Replace homoglyphs
    for cyrillic, ascii_char in HOMOGLYPH_MAP.items():
        text = text.replace(cyrillic, ascii_char)
    
    # Step 5: Normalize whitespace
    text = re.sub(r"[ \t]+", " ", text)  # Collapse spaces/tabs
    text = re.sub(r"\n\n+", "\n", text)  # Collapse newlines
    text = text.strip()
    
    return text


# ============================================================================
# Unicode Analysis
# ============================================================================

def analyze_unicode(text: str) -> Dict[str, Any]:
    """
    Analyze text for Unicode obfuscation.
    
    Args:
        text: Input text
    
    Returns:
        Dictionary with analysis results
    """
    result = {
        "zero_width_count": 0,
        "zero_width_positions": [],
        "invisible_count": 0,
        "bidi_count": 0,
        "homoglyph_count": 0,
        "obfuscation_detected": False,
        "normalization_changes": 0,
    }
    
    # Count zero-width characters
    for i, char in enumerate(text):
        if char in ZERO_WIDTH_CHARS:
            result["zero_width_count"] += 1
            result["zero_width_positions"].append(i)
        if char in BIDI_CHARS:
            result["bidi_count"] += 1
        if char in HOMOGLYPH_MAP:
            result["homoglyph_count"] += 1
        # Check for invisible characters
        if unicodedata.category(char) in ("Cf", "Mn", "Mc"):
            result["invisible_count"] += 1
    
    # Check normalization changes
    normalized = unicodedata.normalize("NFKC", text)
    result["normalization_changes"] = sum(1 for a, b in zip(text, normalized) if a != b)
    
    # Detect obfuscation
    result["obfuscation_detected"] = (
        result["zero_width_count"] > 0 or
        result["bidi_count"] > 0 or
        result["homoglyph_count"] > 2 or
        result["normalization_changes"] > 5
    )
    
    return result


# ============================================================================
# Heuristic Checks
# ============================================================================

def run_heuristics(text: str) -> Dict[str, Any]:
    """
    Run fast heuristic security checks.
    
    Args:
        text: Normalized input text
    
    Returns:
        Dictionary with heuristic results
    """
    result = {
        "has_long_base64": False,
        "has_system_delimiter": False,
        "has_suspicious_keywords": False,
        "has_html_comments": False,
        "has_xml_tags": False,
        "detected_patterns": [],
        "suspicious_score": 0.0,
    }
    
    score = 0.0
    
    for pattern, name in _COMPILED_PATTERNS:
        if pattern.search(text):
            result["detected_patterns"].append(name)
            
            if name == "long_base64":
                result["has_long_base64"] = True
                score += 0.3
            elif name == "system_delimiter":
                result["has_system_delimiter"] = True
                score += 0.4
            elif name in ("ignore_instruction", "disregard_instruction"):
                result["has_suspicious_keywords"] = True
                score += 0.5
            elif name == "html_comment":
                result["has_html_comments"] = True
                score += 0.2
            elif name == "xml_injection":
                result["has_xml_tags"] = True
                score += 0.4
            else:
                score += 0.3
    
    # Check for long lines (possible obfuscation)
    max_line_length = max((len(line) for line in text.split("\n")), default=0)
    if max_line_length > 500:
        result["detected_patterns"].append("long_line")
        score += 0.1
    
    # Check for repeated characters (possible attack padding)
    if re.search(r"(.)\1{20,}", text):
        result["detected_patterns"].append("repeated_chars")
        score += 0.2
    
    result["suspicious_score"] = min(score, 1.0)
    
    return result


# ============================================================================
# Text Embedding
# ============================================================================

@lru_cache(maxsize=1000)
def generate_embedding(text: str) -> Optional[str]:
    """
    Generate text embedding hash for semantic fingerprinting.
    
    Uses sentence-transformers with LRU caching.
    
    Args:
        text: Input text (truncated to first 512 chars for cache efficiency)
    
    Returns:
        SHA256 hash of embedding vector, or None if unavailable
    """
    if not text or not text.strip():
        return None
    
    model = _get_embedding_model()
    if model is None:
        return None
    
    try:
        # Truncate for embedding (most models have 512 token limit anyway)
        truncated = text[:2048]
        embedding = model.encode(truncated, convert_to_numpy=True)
        
        # Create hash of embedding for compact fingerprint
        embedding_bytes = embedding.tobytes()
        return hashlib.sha256(embedding_bytes).hexdigest()[:32]
    except Exception:
        return None


def generate_embedding_with_vector(text: str) -> Optional[Tuple[str, List[float]]]:
    """
    Generate embedding hash and full vector.
    
    Args:
        text: Input text
    
    Returns:
        Tuple of (hash, vector) or None
    """
    if not text or not text.strip():
        return None
    
    model = _get_embedding_model()
    if model is None:
        return None
    
    try:
        truncated = text[:2048]
        embedding = model.encode(truncated, convert_to_numpy=True)
        embedding_bytes = embedding.tobytes()
        hash_val = hashlib.sha256(embedding_bytes).hexdigest()[:32]
        return (hash_val, embedding.tolist())
    except Exception:
        return None


# ============================================================================
# HMAC Operations
# ============================================================================

# Default HMAC key (should be configured via environment in production)
_HMAC_KEY = b"llm-protect-default-key-change-in-production"


def set_hmac_key(key: bytes) -> None:
    """Set the HMAC key for signing operations."""
    global _HMAC_KEY
    _HMAC_KEY = key


def generate_hmac(data: str) -> str:
    """
    Generate HMAC-SHA256 signature for data.
    
    Args:
        data: String data to sign
    
    Returns:
        Hex-encoded HMAC signature
    """
    return hmac.new(
        _HMAC_KEY,
        data.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def generate_hmacs(chunks: List[str]) -> List[str]:
    """
    Generate HMAC signatures for multiple chunks.
    
    Args:
        chunks: List of text chunks
    
    Returns:
        List of HMAC signatures
    """
    return [generate_hmac(chunk) for chunk in chunks]


def verify_hmac(data: str, signature: str) -> bool:
    """
    Verify HMAC signature.
    
    Args:
        data: Original data
        signature: HMAC signature to verify
    
    Returns:
        True if valid, False otherwise
    """
    expected = generate_hmac(data)
    return hmac.compare_digest(expected, signature)


# ============================================================================
# Emoji Extraction
# ============================================================================

# Common emoji descriptions (fallback if emoji lib unavailable)
_EMOJI_DESCRIPTIONS = {
    "😀": "grinning face",
    "😂": "face with tears of joy",
    "🤔": "thinking face",
    "👍": "thumbs up",
    "❤️": "red heart",
    "🔥": "fire",
    "💀": "skull",
    "⚠️": "warning sign",
    "🚨": "police car light",
}


def extract_emojis(text: str) -> Dict[str, Any]:
    """
    Extract emojis from text with descriptions.
    
    Args:
        text: Input text
    
    Returns:
        Dictionary with emoji count, types, and descriptions
    """
    result = {
        "count": 0,
        "types": [],
        "descriptions": [],
    }
    
    emoji_lib = _get_emoji_lib()
    
    if emoji_lib:
        # Use emoji library for accurate extraction
        emoji_list = emoji_lib.emoji_list(text)
        seen = set()
        
        for item in emoji_list:
            char = item["emoji"]
            if char not in seen:
                seen.add(char)
                result["types"].append(char)
                # Get description using demojize
                desc = emoji_lib.demojize(char).strip(":")
                result["descriptions"].append(desc.replace("_", " "))
        
        result["count"] = len(emoji_list)
    else:
        # Fallback: Simple regex extraction
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols
            "\U0001F680-\U0001F6FF"  # transport
            "\U0001F700-\U0001F77F"  # alchemical
            "\U0001F780-\U0001F7FF"  # geometric
            "\U0001F800-\U0001F8FF"  # arrows
            "\U0001F900-\U0001F9FF"  # supplemental
            "\U0001FA00-\U0001FA6F"  # chess
            "\U0001FA70-\U0001FAFF"  # symbols
            "\U00002702-\U000027B0"  # dingbats
            "\U000024C2-\U0001F251"  # enclosed
            "]+"
        )
        
        matches = emoji_pattern.findall(text)
        seen = set()
        
        for emoji_chars in matches:
            for char in emoji_chars:
                if char not in seen:
                    seen.add(char)
                    result["types"].append(char)
                    result["descriptions"].append(
                        _EMOJI_DESCRIPTIONS.get(char, "emoji")
                    )
        
        result["count"] = sum(len(m) for m in matches)
    
    return result


# ============================================================================
# Unified Run Function
# ============================================================================

def run(manifest: "PipelineManifest") -> "PipelineManifest":
    """
    Run full input preparation on a manifest.
    
    This is the main entry point for the input_prep layer.
    
    Args:
        manifest: Pipeline manifest to process
    
    Returns:
        Updated manifest with input_prep_result populated
    """
    from contracts.manifest import ScanStatus
    import time
    
    start = time.perf_counter()
    
    try:
        # Normalize text
        clean_text = normalize_text(manifest.text)
        manifest.clean_text = clean_text
        
        # Unicode analysis
        unicode_result = analyze_unicode(manifest.text)
        manifest.input_prep_result.zero_width_found = unicode_result["zero_width_count"]
        manifest.input_prep_result.invisible_chars_found = unicode_result["invisible_count"]
        manifest.input_prep_result.homoglyphs_replaced = unicode_result["homoglyph_count"]
        manifest.input_prep_result.unicode_obfuscation_detected = unicode_result["obfuscation_detected"]
        
        manifest.flags.zero_width_removed = unicode_result["zero_width_count"] > 0
        manifest.flags.unicode_normalized = True
        manifest.flags.homoglyphs_replaced = unicode_result["homoglyph_count"] > 0
        
        # Heuristics
        heuristic_result = run_heuristics(clean_text)
        manifest.input_prep_result.has_long_base64 = heuristic_result["has_long_base64"]
        manifest.input_prep_result.has_system_delimiter = heuristic_result["has_system_delimiter"]
        manifest.input_prep_result.has_suspicious_keywords = heuristic_result["has_suspicious_keywords"]
        manifest.input_prep_result.suspicious_score = heuristic_result["suspicious_score"]
        manifest.input_prep_result.detected_patterns = heuristic_result["detected_patterns"]
        
        # Text embedding
        embedding_hash = generate_embedding(clean_text)
        manifest.embeddings.text_embedding_hash = embedding_hash
        manifest.embeddings.model_name = "all-MiniLM-L6-v2"
        
        # HMAC for external chunks
        if manifest.external_chunks:
            hmacs = generate_hmacs(manifest.external_chunks)
            manifest.hashes.external_chunks_hmacs = hmacs
            manifest.input_prep_result.external_chunks_count = len(manifest.external_chunks)
            manifest.input_prep_result.hmacs_generated = len(hmacs)
            manifest.flags.hmac_verified = True
        
        # Hash the text
        manifest.hashes.text_sha256 = hashlib.sha256(manifest.text.encode()).hexdigest()
        manifest.hashes.clean_text_sha256 = hashlib.sha256(clean_text.encode()).hexdigest()
        
        # Emoji extraction
        emoji_result = extract_emojis(manifest.text)
        manifest.flags.has_emojis = emoji_result["count"] > 0
        manifest.flags.emoji_count = emoji_result["count"]
        manifest.input_prep_result.emoji_count = emoji_result["count"]
        manifest.input_prep_result.emoji_descriptions = emoji_result["descriptions"]
        
        # Update counts
        manifest.input_prep_result.original_char_count = len(manifest.text)
        manifest.input_prep_result.normalized_char_count = len(clean_text)
        
        # Estimate tokens (rough: ~4 chars per token)
        manifest.input_prep_result.token_estimate = len(clean_text) // 4
        
        # Set score and status
        manifest.input_prep_result.score = heuristic_result["suspicious_score"]
        manifest.prep_score = heuristic_result["suspicious_score"]
        
        if heuristic_result["suspicious_score"] > 0.8:
            manifest.input_prep_result.status = ScanStatus.WARN
            manifest.input_prep_result.note = "High suspicious score from heuristics"
        else:
            manifest.input_prep_result.status = ScanStatus.CLEAN
        
    except Exception as e:
        manifest.input_prep_result.status = ScanStatus.ERROR
        manifest.input_prep_result.note = str(e)
    
    manifest.input_prep_result.processing_time_ms = (time.perf_counter() - start) * 1000
    
    return manifest
