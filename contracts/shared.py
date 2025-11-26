"""
Shared utilities for LLM-Protect pipeline.

This module consolidates shared functionality to eliminate redundancy:
- Embedding model (lazy-loaded, cached, single instance)
- Hashing utilities (unified across layers)
- Text normalization (shared implementation)
"""

import hashlib
import hmac
from functools import lru_cache
from typing import List, Optional, Tuple

import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Singleton Model Holders
# ============================================================================

class ModelManager:
    """
    Manages lazy-loaded ML models as singletons.
    
    Ensures models are loaded only once and shared across layers.
    """
    
    _embedding_model = None
    _embedding_model_loaded = False
    
    @classmethod
    def get_embedding_model(cls):
        """
        Get the sentence transformer model (singleton).
        
        Returns:
            SentenceTransformer model or None if unavailable
        """
        if not cls._embedding_model_loaded:
            cls._embedding_model_loaded = True
            try:
                from sentence_transformers import SentenceTransformer
                cls._embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
                logger.info("Loaded sentence transformer model")
            except ImportError:
                logger.warning("sentence-transformers not available")
                cls._embedding_model = None
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}")
                cls._embedding_model = None
        
        return cls._embedding_model
    
    @classmethod
    def unload_models(cls):
        """Unload all models to free memory."""
        cls._embedding_model = None
        cls._embedding_model_loaded = False


# ============================================================================
# Hashing Utilities (Unified)
# ============================================================================

def hash_sha256(data: bytes) -> str:
    """Compute SHA256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_file_sha256(file_path: str) -> str:
    """Compute SHA256 hash of file."""
    with open(file_path, "rb") as f:
        return hash_sha256(f.read())


def hash_string_sha256(text: str) -> str:
    """Compute SHA256 hash of string."""
    return hash_sha256(text.encode("utf-8"))


class HMACManager:
    """
    Manages HMAC operations with configurable key.
    """
    
    _key: bytes = b"llm-protect-default-key"
    
    @classmethod
    def set_key(cls, key: bytes):
        """Set the HMAC key."""
        cls._key = key
    
    @classmethod
    def sign(cls, data: str) -> str:
        """Generate HMAC-SHA256 signature."""
        return hmac.new(
            cls._key,
            data.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
    
    @classmethod
    def verify(cls, data: str, signature: str) -> bool:
        """Verify HMAC signature (constant-time)."""
        expected = cls.sign(data)
        return hmac.compare_digest(expected, signature)
    
    @classmethod
    def sign_chunks(cls, chunks: List[str]) -> List[str]:
        """Sign multiple chunks."""
        return [cls.sign(chunk) for chunk in chunks]


# ============================================================================
# Embedding Utilities (Unified, Cached)
# ============================================================================

# LRU cache for embeddings (avoid recomputing)
_embedding_cache = {}
_CACHE_MAX_SIZE = 1000


def generate_embedding_hash(text: str) -> Optional[str]:
    """
    Generate embedding fingerprint hash.
    
    Uses LRU caching to avoid recomputation.
    """
    if not text or not text.strip():
        return None
    
    # Check cache
    cache_key = hash_string_sha256(text[:512])  # Use truncated hash as key
    if cache_key in _embedding_cache:
        return _embedding_cache[cache_key]
    
    model = ModelManager.get_embedding_model()
    if model is None:
        return None
    
    try:
        # Truncate for embedding
        truncated = text[:2048]
        embedding = model.encode(truncated, convert_to_numpy=True)
        
        # Hash the embedding
        embedding_hash = hash_sha256(embedding.tobytes())[:32]
        
        # Cache it
        if len(_embedding_cache) >= _CACHE_MAX_SIZE:
            # Simple eviction: clear half
            keys = list(_embedding_cache.keys())[:_CACHE_MAX_SIZE // 2]
            for k in keys:
                del _embedding_cache[k]
        
        _embedding_cache[cache_key] = embedding_hash
        
        return embedding_hash
        
    except Exception as e:
        logger.error(f"Embedding generation failed: {e}")
        return None


def generate_embedding_with_vector(text: str) -> Optional[Tuple[str, List[float]]]:
    """Generate embedding hash and full vector."""
    if not text or not text.strip():
        return None
    
    model = ModelManager.get_embedding_model()
    if model is None:
        return None
    
    try:
        truncated = text[:2048]
        embedding = model.encode(truncated, convert_to_numpy=True)
        embedding_hash = hash_sha256(embedding.tobytes())[:32]
        return (embedding_hash, embedding.tolist())
    except Exception as e:
        logger.error(f"Embedding with vector failed: {e}")
        return None


def clear_embedding_cache():
    """Clear the embedding cache."""
    global _embedding_cache
    _embedding_cache = {}


# ============================================================================
# Text Normalization (Unified)
# ============================================================================

# Import from input_prep.core or define here as fallback
try:
    from input_prep.core import normalize_text, analyze_unicode
except ImportError:
    import re
    import unicodedata
    
    ZERO_WIDTH_CHARS = {
        "\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u180e",
    }
    BIDI_CHARS = {
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
        "\u2066", "\u2067", "\u2068", "\u2069",
    }
    HOMOGLYPH_MAP = {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    }
    
    def normalize_text(text: str) -> str:
        """Normalize text (fallback implementation)."""
        if not text:
            return ""
        text = unicodedata.normalize("NFKC", text)
        for char in ZERO_WIDTH_CHARS:
            text = text.replace(char, "")
        for char in BIDI_CHARS:
            text = text.replace(char, "")
        for src, dst in HOMOGLYPH_MAP.items():
            text = text.replace(src, dst)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\n+", "\n", text)
        return text.strip()
    
    def analyze_unicode(text: str) -> dict:
        """Analyze unicode (fallback implementation)."""
        return {
            "zero_width_count": sum(1 for c in text if c in ZERO_WIDTH_CHARS),
            "obfuscation_detected": any(c in text for c in ZERO_WIDTH_CHARS),
        }


# ============================================================================
# Exports
# ============================================================================

__all__ = [
    "ModelManager",
    "hash_sha256",
    "hash_file_sha256",
    "hash_string_sha256",
    "HMACManager",
    "generate_embedding_hash",
    "generate_embedding_with_vector",
    "clear_embedding_cache",
    "normalize_text",
    "analyze_unicode",
]
