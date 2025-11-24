"""
Guard Service - Main Public API for the Security Guard System.

This module provides the primary entry point for the security guard system,
orchestrating all pipelines and making final allow/rewrite/block decisions.
"""

import time
from typing import Optional, Dict, Any

from security.core.types import (
    IncomingRequest,
    GuardResult,
    GuardAction,
    Verdict,
)
from security.pipelines.image_pipeline import build_image_feature_pack
from security.pipelines.emoji_pipeline import build_emoji_feature_pack
from security.fusion.fusion_layer import build_fusion_features
from security.detection.anomaly_detector import compute_anomaly_decision
from config.security_config import (
    REWRITE_MESSAGES,
    BLOCK_MESSAGES,
    SANITIZE_ZERO_WIDTH,
    SANITIZE_BIDI_OVERRIDE,
    FAIL_CLOSED_ON_ERROR,
    ZERO_WIDTH_CHARS,
    BIDI_OVERRIDE_CHARS,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# Text Sanitization
# ============================================================================

def sanitize_text(text: str) -> str:
    """
    Sanitize text by removing ONLY invisible Unicode threats.
    
    IMPORTANT: Never alter visible content (emojis, regular text).
    Only remove zero-width characters and normalize bidi overrides.
    
    Args:
        text: Input text
        
    Returns:
        Sanitized text with invisible threats removed
    """
    sanitized = text
    
    # Remove zero-width characters
    if SANITIZE_ZERO_WIDTH:
        for zwc in ZERO_WIDTH_CHARS:
            sanitized = sanitized.replace(zwc, '')
    
    # Remove bidi override characters
    if SANITIZE_BIDI_OVERRIDE:
        for bidi in BIDI_OVERRIDE_CHARS:
            sanitized = sanitized.replace(bidi, '')
    
    # Log if sanitization occurred
    if sanitized != text:
        removed_count = len(text) - len(sanitized)
        logger.info(f"Sanitized text: removed {removed_count} invisible characters")
    
    return sanitized


# ============================================================================
# Message Generation
# ============================================================================

def generate_rewrite_message(reasons: list) -> str:
    """
    Generate user-facing message for rewrite action.
    
    IMPORTANT: Be helpful but security-conscious.
    Never reveal specific detection logic.
    
    Args:
        reasons: List of generic reasons
        
    Returns:
        Generic, helpful message asking user to revise
    """
    # Determine message type based on reasons
    if any("image" in r.lower() for r in reasons):
        return REWRITE_MESSAGES["image"]
    elif any("formatting" in r.lower() or "characters" in r.lower() for r in reasons):
        return REWRITE_MESSAGES["unicode"]
    elif any("emoji" in r.lower() or "content" in r.lower() for r in reasons):
        return REWRITE_MESSAGES["emoji"]
    else:
        return REWRITE_MESSAGES["generic"]


def generate_block_message(reasons: list, is_error: bool = False) -> str:
    """
    Generate user-facing message for block action.
    
    Args:
        reasons: List of generic reasons
        is_error: Whether block is due to internal error
        
    Returns:
        Generic block message
    """
    if is_error:
        return BLOCK_MESSAGES["error"]
    elif len(reasons) > 0:
        return BLOCK_MESSAGES["high_threat"]
    else:
        return BLOCK_MESSAGES["generic"]


# ============================================================================
# Main Guard Function
# ============================================================================

def guard_request(input_request: IncomingRequest, debug: bool = False) -> GuardResult:
    """
    Main security guard function - orchestrates all pipelines and makes decision.
    
    This is a synchronous wrapper around the async implementation.
    
    Args:
        input_request: Incoming request with text/image/metadata
        debug: Enable debug output in result
        
    Returns:
        GuardResult with action, reasons, sanitized text, and optional debug info
    """
    import asyncio
    
    # Run the async version
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(_guard_request_async(input_request, debug))


async def _guard_request_async(input_request: IncomingRequest, debug: bool = False) -> GuardResult:
    """
    Main security guard function (async implementation).
    
    Pipeline flow:
    1. Parse and validate input
    2. Run image pipeline (if image present)
    3. Run emoji/text pipeline (if text present)
    4. Fuse features
    5. Detect anomalies
    6. Make decision (allow/rewrite/block)
    7. Return result
    
    Error handling: Fail-closed (block on errors) with loud logging.
    
    Args:
        input_request: Incoming request with text/image/metadata
        debug: Enable debug output in result
        
    Returns:
        GuardResult with action, reasons, sanitized text, and optional debug info
        
    Example:
        >>> request = IncomingRequest(text="Hello world!", image_bytes=None)
        >>> result = await _guard_request_async(request)
        >>> result.action
        GuardAction.ALLOW
        >>> result.sanitized_text
        "Hello world!"
    """
    start_time = time.time()
    
    try:
        # === Step 1: Validate input ===
        if not input_request.text and not input_request.image_bytes:
            logger.warning("Empty request received")
            return GuardResult(
                action=GuardAction.BLOCK,
                reasons=["Empty request"],
                anomaly_score=0.0,
                sanitized_text="",
                message=BLOCK_MESSAGES["generic"]
            )
        
        # === Step 2: Run image pipeline (if image present) ===
        image_pack = None
        if input_request.image_bytes:
            try:
                logger.info("Running image pipeline...")
                image_pack = await build_image_feature_pack(input_request.image_bytes)
            except Exception as e:
                logger.error(f"Image pipeline failed: {e}", exc_info=True)
                if FAIL_CLOSED_ON_ERROR:
                    return GuardResult(
                        action=GuardAction.BLOCK,
                        reasons=["Image processing failed"],
                        anomaly_score=1.0,
                        sanitized_text="",
                        message=generate_block_message([], is_error=True),
                        debug={"error": str(e)} if debug else None
                    )
        
        # === Step 3: Run emoji/text pipeline (if text present) ===
        emoji_pack = None
        if input_request.text:
            try:
                logger.info("Running emoji/text pipeline...")
                emoji_pack = await build_emoji_feature_pack(input_request.text)
            except Exception as e:
                logger.error(f"Emoji/text pipeline failed: {e}", exc_info=True)
                if FAIL_CLOSED_ON_ERROR:
                    return GuardResult(
                        action=GuardAction.BLOCK,
                        reasons=["Text processing failed"],
                        anomaly_score=1.0,
                        sanitized_text="",
                        message=generate_block_message([], is_error=True),
                        debug={"error": str(e)} if debug else None
                    )
        
        # === Step 4: Fuse features ===
        try:
            logger.info("Fusing features...")
            fusion_features = build_fusion_features(input_request, image_pack, emoji_pack)
        except Exception as e:
            logger.error(f"Feature fusion failed: {e}", exc_info=True)
            if FAIL_CLOSED_ON_ERROR:
                return GuardResult(
                    action=GuardAction.BLOCK,
                    reasons=["Feature fusion failed"],
                    anomaly_score=1.0,
                    sanitized_text="",
                    message=generate_block_message([], is_error=True),
                    debug={"error": str(e)} if debug else None
                )
        
        # === Step 5: Detect anomalies ===
        try:
            logger.info("Detecting anomalies...")
            anomaly_decision = compute_anomaly_decision(fusion_features)
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}", exc_info=True)
            if FAIL_CLOSED_ON_ERROR:
                return GuardResult(
                    action=GuardAction.BLOCK,
                    reasons=["Anomaly detection failed"],
                    anomaly_score=1.0,
                    sanitized_text="",
                    message=generate_block_message([], is_error=True),
                    debug={"error": str(e)} if debug else None
                )
        
        # === Step 6: Make decision ===
        elapsed_time = time.time() - start_time
        
        if anomaly_decision.verdict == Verdict.PASS:
            # ALLOW: Sanitize only invisible Unicode threats
            sanitized = sanitize_text(input_request.text) if input_request.text else ""
            
            logger.info(f"Request ALLOWED (score={anomaly_decision.anomaly_score:.3f}, time={elapsed_time:.3f}s)")
            return GuardResult(
                action=GuardAction.ALLOW,
                reasons=anomaly_decision.reasons,
                anomaly_score=anomaly_decision.anomaly_score,
                sanitized_text=sanitized,
                message=None,
                debug={
                    "fusion_features": fusion_features.dict() if debug else None,
                    "anomaly_decision": anomaly_decision.dict() if debug else None,
                    "elapsed_time": elapsed_time
                } if debug else None
            )
        
        elif anomaly_decision.verdict == Verdict.BORDERLINE:
            # REWRITE: Ask user to revise
            message = generate_rewrite_message(anomaly_decision.reasons)
            
            logger.info(f"Request REWRITE (score={anomaly_decision.anomaly_score:.3f}, time={elapsed_time:.3f}s)")
            return GuardResult(
                action=GuardAction.REWRITE,
                reasons=anomaly_decision.reasons,
                anomaly_score=anomaly_decision.anomaly_score,
                sanitized_text="",
                message=message,
                debug={
                    "fusion_features": fusion_features.dict() if debug else None,
                    "anomaly_decision": anomaly_decision.dict() if debug else None,
                    "elapsed_time": elapsed_time
                } if debug else None
            )
        
        else:  # Verdict.FAIL
            # BLOCK: Reject request
            message = generate_block_message(anomaly_decision.reasons, is_error=False)
            
            logger.warning(f"Request BLOCKED (score={anomaly_decision.anomaly_score:.3f}, time={elapsed_time:.3f}s)")
            return GuardResult(
                action=GuardAction.BLOCK,
                reasons=anomaly_decision.reasons,
                anomaly_score=anomaly_decision.anomaly_score,
                sanitized_text="",
                message=message,
                debug={
                    "fusion_features": fusion_features.dict() if debug else None,
                    "anomaly_decision": anomaly_decision.dict() if debug else None,
                    "elapsed_time": elapsed_time
                } if debug else None
            )
    
    except Exception as e:
        # Catch-all for any unexpected errors
        logger.error(f"Guard request failed with unexpected error: {e}", exc_info=True)
        
        if FAIL_CLOSED_ON_ERROR:
            return GuardResult(
                action=GuardAction.BLOCK,
                reasons=["Internal security check failed"],
                anomaly_score=1.0,
                sanitized_text="",
                message=BLOCK_MESSAGES["error"],
                debug={"error": str(e), "error_type": type(e).__name__} if debug else None
            )
        else:
            # Fail-open (not recommended for security)
            logger.warning("Failing open due to error (FAIL_CLOSED_ON_ERROR=False)")
            return GuardResult(
                action=GuardAction.ALLOW,
                reasons=["Security check bypassed due to error"],
                anomaly_score=0.0,
                sanitized_text=input_request.text or "",
                message=None,
                debug={"error": str(e), "error_type": type(e).__name__} if debug else None
            )


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "sanitize_text",
    "generate_rewrite_message",
    "generate_block_message",
    "guard_request",
]
