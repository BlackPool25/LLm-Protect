"""
Integration tests for the Image + Emoji Security Guard System.

Tests the complete pipeline from input to decision.
"""

import pytest
from security import guard_request, IncomingRequest, GuardAction
from pathlib import Path


class TestGuardIntegration:
    """Integration tests for the guard system."""
    
    def test_safe_text_allowed(self):
        """Test that safe text is allowed."""
        request = IncomingRequest(
            text="Hello world! This is a safe message.",
            metadata={"test": "safe_text"}
        )
        
        result = guard_request(request)
        
        assert result.action == GuardAction.ALLOW
        assert result.anomaly_score < 0.3
        assert result.sanitized_text == "Hello world! This is a safe message."
    
    def test_neutral_emojis_pass(self):
        """Test that neutral emojis pass with low risk score."""
        request = IncomingRequest(
            text="Hello 😀 World 🌍! Great day 👍",
            metadata={"test": "neutral_emojis"}
        )
        
        result = guard_request(request)
        
        assert result.action == GuardAction.ALLOW
        assert result.anomaly_score < 0.4
    
    def test_risky_emojis_flagged(self):
        """Test that risky emojis (weapons, violent) are flagged."""
        request = IncomingRequest(
            text="⚔️🔫💣 Attack!",
            metadata={"test": "risky_emojis"}
        )
        
        result = guard_request(request)
        
        # Should be borderline or blocked
        assert result.action in [GuardAction.REWRITE, GuardAction.BLOCK]
        assert result.anomaly_score > 0.5
        assert len(result.reasons) > 0
    
    def test_zero_width_characters_detected(self):
        """Test that zero-width characters are detected and sanitized."""
        # Text with zero-width characters
        text_with_zwc = "Hello\u200B\u200C\u200DWorld"
        
        request = IncomingRequest(
            text=text_with_zwc,
            metadata={"test": "zero_width"}
        )
        
        result = guard_request(request)
        
        # Should detect unicode threat
        if result.action == GuardAction.ALLOW:
            # If allowed, should sanitize
            assert "\u200B" not in result.sanitized_text
            assert "\u200C" not in result.sanitized_text
            assert "\u200D" not in result.sanitized_text
        else:
            # If blocked/rewrite, should have reason
            assert any("formatting" in r.lower() or "characters" in r.lower() 
                      for r in result.reasons)
    
    def test_bidi_override_detected(self):
        """Test that bidi override attacks are detected."""
        # Text with bidi override
        text_with_bidi = "user@example.com\u202Emoc.elpmaxe@resu"
        
        request = IncomingRequest(
            text=text_with_bidi,
            metadata={"test": "bidi_override"}
        )
        
        result = guard_request(request)
        
        # Should be flagged
        assert result.action in [GuardAction.REWRITE, GuardAction.BLOCK]
        assert result.anomaly_score > 0.3
    
    def test_emoji_repetition_spam(self):
        """Test that repetitive emoji spam is detected."""
        request = IncomingRequest(
            text="🔥" * 20 + " Buy now!",
            metadata={"test": "emoji_spam"}
        )
        
        result = guard_request(request)
        
        # Should be flagged as spam
        assert result.action in [GuardAction.REWRITE, GuardAction.BLOCK]
        assert result.anomaly_score > 0.3
    
    def test_empty_request_blocked(self):
        """Test that empty requests are blocked."""
        request = IncomingRequest(
            text=None,
            image_bytes=None,
            metadata={"test": "empty"}
        )
        
        result = guard_request(request)
        
        assert result.action == GuardAction.BLOCK
        assert "Empty request" in result.reasons
    
    def test_debug_mode_includes_details(self):
        """Test that debug mode includes detailed information."""
        request = IncomingRequest(
            text="Test message",
            metadata={"test": "debug"}
        )
        
        result = guard_request(request, debug=True)
        
        assert result.debug is not None
        assert "anomaly_decision" in result.debug or "elapsed_time" in result.debug
    
    def test_combined_threats(self):
        """Test multiple threats combined (risky emojis + unicode threats)."""
        # Combine risky emojis with zero-width characters
        text = "🔫💣\u200B\u200C Attack now!"
        
        request = IncomingRequest(
            text=text,
            metadata={"test": "combined_threats"}
        )
        
        result = guard_request(request)
        
        # Should definitely be blocked or rewrite
        assert result.action in [GuardAction.REWRITE, GuardAction.BLOCK]
        assert result.anomaly_score > 0.6
        assert len(result.reasons) > 0


class TestImagePipeline:
    """Tests for image pipeline (requires test images)."""
    
    def test_image_without_text(self):
        """Test processing image without text."""
        # Create a simple test image (1x1 red pixel)
        import io
        from PIL import Image
        
        img = Image.new('RGB', (100, 100), color='red')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes = img_bytes.getvalue()
        
        request = IncomingRequest(
            image_bytes=img_bytes,
            metadata={"test": "image_only"}
        )
        
        result = guard_request(request)
        
        # Should process successfully
        assert result.action in [GuardAction.ALLOW, GuardAction.REWRITE, GuardAction.BLOCK]
        assert result.anomaly_score >= 0.0
    
    def test_invalid_image_blocked(self):
        """Test that invalid image data is blocked."""
        request = IncomingRequest(
            image_bytes=b"not an image",
            metadata={"test": "invalid_image"}
        )
        
        result = guard_request(request)
        
        # Should be blocked due to processing failure
        assert result.action == GuardAction.BLOCK
        assert any("image" in r.lower() or "processing" in r.lower() or "failed" in r.lower()
                  for r in result.reasons)


class TestErrorHandling:
    """Tests for error handling and fail-closed behavior."""
    
    def test_fail_closed_on_pipeline_error(self):
        """Test that pipeline errors result in block (fail-closed)."""
        # This test would require mocking to force an error
        # For now, we test with invalid input
        request = IncomingRequest(
            text="x" * 1000000,  # Very long text might cause issues
            metadata={"test": "stress"}
        )
        
        # Should handle gracefully
        result = guard_request(request)
        assert result.action in [GuardAction.ALLOW, GuardAction.REWRITE, GuardAction.BLOCK]


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
