"""
Security configuration for the Image + Emoji Security Guard System.

This module contains all configurable thresholds, weights, and parameters
for anomaly detection and decision-making.
"""

# ============================================================================
# Anomaly Detection Thresholds
# ============================================================================

# Score thresholds for verdict determination
ANOMALY_THRESHOLDS = {
    "pass": 0.3,        # score < 0.3 → pass (allow)
    "borderline": 0.6,  # 0.3 <= score < 0.6 → borderline (ask to rewrite)
    "fail": 0.6         # score >= 0.6 → fail (block)
}

# Feature-specific thresholds
STEGO_HIGH_THRESHOLD = 0.7          # Steganography score considered high
EMOJI_RISK_HIGH_THRESHOLD = 0.6     # Emoji risk score considered high
UNICODE_THREAT_THRESHOLD = 0.5      # Unicode threat score threshold

# Pattern detection thresholds
EMOJI_REPETITION_THRESHOLD = 0.3    # Repetition score threshold
PATTERN_COMPLEXITY_THRESHOLD = 0.5  # Pattern complexity threshold


# ============================================================================
# Feature Weights for Anomaly Scoring
# ============================================================================

# Weights for different threat categories (used in heuristic scoring)
FEATURE_WEIGHTS = {
    "stego_score": 0.3,           # Weight for steganography detection
    "emoji_risk_score": 0.25,     # Weight for emoji risk
    "unicode_threats": 0.4,       # Weight for Unicode threats
    "pattern_injection": 0.5,     # Weight for prompt injection patterns
    "emoji_cipher": 0.3,          # Weight for emoji cipher patterns
}

# Maximum possible anomaly score (for normalization)
MAX_ANOMALY_SCORE = 1.0


# ============================================================================
# Image Processing Configuration
# ============================================================================

# Image preprocessing settings
IMAGE_TARGET_SIZE = (64, 64)        # Target size for image downscaling
IMAGE_EMBEDDING_DIM = 128           # Dimension of image embedding vector
MAX_IMAGE_SIZE_MB = 10              # Maximum image size in MB
SUPPORTED_IMAGE_FORMATS = ["PNG", "JPEG", "JPG", "GIF", "BMP", "WEBP"]

# Image sanity check limits
MAX_IMAGE_WIDTH = 4096              # Maximum image width in pixels
MAX_IMAGE_HEIGHT = 4096             # Maximum image height in pixels
MIN_IMAGE_WIDTH = 16                # Minimum image width in pixels
MIN_IMAGE_HEIGHT = 16               # Minimum image height in pixels


# ============================================================================
# Text Processing Configuration
# ============================================================================

# Emoji pattern detection settings
MIN_EMOJI_REPETITION_COUNT = 3      # Minimum repetitions to flag as spam
EMOJI_CIPHER_MIN_LENGTH = 5         # Minimum length for cipher detection
MAX_TEXT_LENGTH = 100000            # Maximum text length in characters

# Unicode threat detection settings
ZERO_WIDTH_CHARS = [
    '\u200B',  # Zero-width space
    '\u200C',  # Zero-width non-joiner
    '\u200D',  # Zero-width joiner
    '\uFEFF',  # Zero-width no-break space
]

BIDI_OVERRIDE_CHARS = [
    '\u202A',  # Left-to-right embedding
    '\u202B',  # Right-to-left embedding
    '\u202C',  # Pop directional formatting
    '\u202D',  # Left-to-right override
    '\u202E',  # Right-to-left override
]


# ============================================================================
# Decision Layer Configuration
# ============================================================================

# User-facing messages (generic, security-conscious)
REWRITE_MESSAGES = {
    "generic": "Your message contains content that may violate our safety guidelines. Please revise and resubmit.",
    "image": "The uploaded image contains patterns that cannot be processed. Please try a different image.",
    "emoji": "Your message contains content that may not be appropriate. Please revise.",
    "unicode": "Your message contains formatting that cannot be processed. Please use standard text.",
}

BLOCK_MESSAGES = {
    "generic": "Your request has been blocked due to security concerns.",
    "high_threat": "Your request contains content that violates our safety policies.",
    "error": "Internal security check failed. Please try again or contact support.",
}

# Sanitization settings
SANITIZE_ZERO_WIDTH = True          # Remove zero-width characters
SANITIZE_BIDI_OVERRIDE = True       # Normalize bidi overrides
SANITIZE_VISIBLE_CONTENT = False    # Never alter visible content (emojis, text)


# ============================================================================
# Performance & Caching Configuration
# ============================================================================

# Timeout settings (in seconds)
IMAGE_PIPELINE_TIMEOUT = 30         # Maximum time for image pipeline
EMOJI_PIPELINE_TIMEOUT = 10         # Maximum time for emoji pipeline
TOTAL_GUARD_TIMEOUT = 60            # Maximum total time for guard_request

# Caching settings
ENABLE_FEATURE_CACHE = True         # Enable caching of feature extractions
CACHE_TTL_SECONDS = 3600            # Cache time-to-live (1 hour)
CACHE_MAX_SIZE = 10000              # Maximum cache entries


# ============================================================================
# Debug & Logging Configuration
# ============================================================================

# Debug mode settings
DEBUG_MODE = False                  # Enable debug output in GuardResult
LOG_LEVEL = "INFO"                  # Logging level
LOG_ANOMALY_SCORES = True           # Log all anomaly scores
LOG_FEATURE_VECTORS = False         # Log feature vectors (verbose)

# Error handling
FAIL_CLOSED_ON_ERROR = True         # Block requests on pipeline errors
LOG_ERRORS_LOUDLY = True            # Log errors with full stack traces


# ============================================================================
# Emoji Risk Map Configuration
# ============================================================================

# Path to emoji risk map JSON file
EMOJI_RISK_MAP_PATH = "config/emoji_risk_map.json"

# Fallback emoji risk scores (if JSON not available)
FALLBACK_EMOJI_RISK_SCORES = {
    "violent": 0.9,
    "weapons": 0.9,
    "self_harm": 0.9,
    "aggressive": 0.7,
    "sexual": 0.7,
    "drugs": 0.7,
    "crypto_scams": 0.5,
    "spam": 0.5,
    "neutral": 0.1,
}


# ============================================================================
# Export Configuration
# ============================================================================

__all__ = [
    "ANOMALY_THRESHOLDS",
    "STEGO_HIGH_THRESHOLD",
    "EMOJI_RISK_HIGH_THRESHOLD",
    "UNICODE_THREAT_THRESHOLD",
    "FEATURE_WEIGHTS",
    "IMAGE_TARGET_SIZE",
    "IMAGE_EMBEDDING_DIM",
    "SUPPORTED_IMAGE_FORMATS",
    "REWRITE_MESSAGES",
    "BLOCK_MESSAGES",
    "EMOJI_RISK_MAP_PATH",
    "FAIL_CLOSED_ON_ERROR",
]
