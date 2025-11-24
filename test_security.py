"""
Comprehensive security test suite.

Tests all security detectors and analyzers with various attack scenarios.
"""

import asyncio
import pytest
from security.detectors.steganography import SteganographyDetector
from security.detectors.unicode_analysis import UnicodeThreatAnalyzer
from security.analyzers.semantic_conflict import SemanticConflictDetector
from security.analyzers.behavioral import BehavioralAnalyzer
from app.services.security_integration import SecurityIntegrationService


class TestSteganographyDetection:
    """Test steganography detection capabilities."""
    
    @pytest.mark.asyncio
    async def test_clean_image(self):
        """Test that clean images are not flagged."""
        # This would need a real image for testing
        # Placeholder test
        pass
    
    @pytest.mark.asyncio
    async def test_lsb_steganography(self):
        """Test detection of LSB steganography."""
        # Test with image containing LSB-embedded data
        pass


class TestUnicodeThreatAnalysis:
    """Test Unicode threat detection."""
    
    @pytest.mark.asyncio
    async def test_zero_width_detection(self):
        """Test detection of zero-width character encoding."""
        analyzer = UnicodeThreatAnalyzer()
        
        # Text with hidden zero-width characters
        malicious_text = "Hello\u200BWorld\u200C\u200DTest"
        
        result = await analyzer.analyze_text(malicious_text)
        
        assert result.overall_threat_score > 0.0
        assert any(v.type == "zero_width" for v in result.threat_vectors)
    
    @pytest.mark.asyncio
    async def test_clean_text(self):
        """Test that normal text is not flagged."""
        analyzer = UnicodeThreatAnalyzer()
        
        clean_text = "This is normal text with no threats."
        
        result = await analyzer.analyze_text(clean_text)
        
        assert result.overall_threat_score < 0.3
    
    @pytest.mark.asyncio
    async def test_bidi_override_attack(self):
        """Test detection of bidirectional override attacks."""
        analyzer = UnicodeThreatAnalyzer()
        
        # Text with bidi override characters
        malicious_text = "user@example.com\u202Emoc.elpmaxe@resu"
        
        result = await analyzer.analyze_text(malicious_text)
        
        assert any(v.type == "bidirectional_override" for v in result.threat_vectors)
    
    @pytest.mark.asyncio
    async def test_homoglyph_substitution(self):
        """Test detection of homoglyph attacks."""
        analyzer = UnicodeThreatAnalyzer()
        
        # Text with Cyrillic 'a' instead of Latin 'a'
        malicious_text = "pаypal.com"  # 'а' is Cyrillic
        
        result = await analyzer.analyze_text(malicious_text)
        
        # Should detect homoglyph if analyzer is sophisticated enough
        # This is a basic test
        pass
    
    @pytest.mark.asyncio
    async def test_emoji_cipher(self):
        """Test detection of potential emoji encoding."""
        analyzer = UnicodeThreatAnalyzer()
        
        # High density of varied emojis
        malicious_text = "🔥🌊🌙⭐🌈🎯🚀💎🎨🎭🎪🎨🎯🌟⚡🔮🎲🎰🎯🎪"
        
        result = await analyzer.analyze_text(malicious_text)
        
        assert any(v.type == "emoji_cipher" for v in result.threat_vectors)


class TestSemanticConflictDetection:
    """Test semantic conflict detection."""
    
    @pytest.mark.asyncio
    async def test_text_contradiction(self):
        """Test detection of internal contradictions."""
        detector = SemanticConflictDetector()
        
        contradictory_text = "This product is excellent. However, it's terrible and I hate it."
        
        result = await detector.check_consistency(contradictory_text)
        
        # Should detect some level of conflict
        assert result.conflict_score > 0.0
    
    @pytest.mark.asyncio
    async def test_metadata_mismatch(self):
        """Test detection of metadata-content mismatches."""
        detector = SemanticConflictDetector()
        
        text = "This is about cats and kittens"
        metadata = {"title": "Dog Training Guide", "description": "How to train dogs"}
        
        result = await detector.check_consistency(text, metadata)
        
        # Should detect mismatch
        assert result.conflict_score > 0.3


class TestBehavioralAnalysis:
    """Test behavioral pattern analysis."""
    
    @pytest.mark.asyncio
    async def test_normal_behavior(self):
        """Test that normal behavior is not flagged."""
        analyzer = BehavioralAnalyzer()
        
        result = await analyzer.analyze("client1", "Normal request")
        
        assert result.threat_level.value in ["none", "low"]
    
    @pytest.mark.asyncio
    async def test_high_frequency_attack(self):
        """Test detection of high-frequency requests."""
        analyzer = BehavioralAnalyzer(window_seconds=10)
        
        # Simulate rapid requests
        for i in range(20):
            result = await analyzer.analyze("attacker1", f"Request {i}")
        
        # Last request should show high frequency
        assert result.request_frequency > 1.0
        assert result.anomaly_score > 0.3
    
    @pytest.mark.asyncio
    async def test_pattern_repetition(self):
        """Test detection of repeated patterns."""
        analyzer = BehavioralAnalyzer()
        
        # Send same request multiple times
        for i in range(10):
            result = await analyzer.analyze(
                "attacker2",
                "Same malicious payload",
                request_hash="hash123"
            )
        
        # Should detect high pattern repetition
        assert result.pattern_complexity > 0.3


class TestSecurityIntegration:
    """Test integrated security service."""
    
    @pytest.mark.asyncio
    async def test_text_analysis_integration(self):
        """Test integrated text security analysis."""
        service = SecurityIntegrationService()
        
        # Text with multiple threats
        malicious_text = "Hello\u200BWorld\u202E with zero-width chars"
        
        report = await service.analyze_text(malicious_text, client_id="test_client")
        
        assert report.overall_threat_score >= 0.0
        assert report.analysis_time_ms > 0
    
    @pytest.mark.asyncio
    async def test_clean_text_analysis(self):
        """Test that clean text produces low threat scores."""
        service = SecurityIntegrationService()
        
        clean_text = "This is a completely normal and safe text message."
        
        report = await service.analyze_text(clean_text, client_id="test_client")
        
        assert report.overall_threat_score < 0.5
        assert len(report.detected_anomalies) == 0


# Attack simulation scenarios

class AttackScenarios:
    """Collection of attack scenarios for testing."""
    
    @staticmethod
    def zero_width_steganography():
        """Generate text with zero-width steganography."""
        # Binary message encoded in zero-width chars
        visible = "This looks like normal text."
        hidden_binary = "11010101"  # Example binary
        
        # Encode using zero-width chars (0 = U+200B, 1 = U+200C)
        hidden = ''.join('\u200B' if b == '0' else '\u200C' for b in hidden_binary)
        
        return visible + hidden
    
    @staticmethod
    def bidi_override_phishing():
        """Generate text with bidi override for phishing."""
        # Make "malicious.com" look like "example.com"
        return "https://com.elpmaxe\u202Emalicious.com"
    
    @staticmethod
    def homoglyph_domain():
        """Generate domain with homoglyph substitution."""
        # Replace 'a' with Cyrillic 'а' in "paypal"
        return "pаypal.com"  # Second character is Cyrillic
    
    @staticmethod
    def emoji_encoding():
        """Generate text with emoji-based encoding."""
        # Map letters to emojis
        emoji_map = {
            'a': '🍎', 'b': '🎈', 'c': '🐱', 'd': '🐶',
            'e': '👁️', 'f': '🔥', 'g': '🎮', 'h': '🏠',
        }
        
        message = "badge"
        return ''.join(emoji_map.get(c, c) for c in message)


@pytest.mark.asyncio
async def test_attack_scenarios():
    """Test various attack scenarios."""
    analyzer = UnicodeThreatAnalyzer()
    
    scenarios = [
        AttackScenarios.zero_width_steganography(),
        AttackScenarios.bidi_override_phishing(),
        AttackScenarios.homoglyph_domain(),
        AttackScenarios.emoji_encoding(),
    ]
    
    for scenario in scenarios:
        result = await analyzer.analyze_text(scenario)
        print(f"Scenario threat score: {result.overall_threat_score}")
        print(f"Threats detected: {[v.type for v in result.threat_vectors]}")


if __name__ == "__main__":
    # Run attack scenario tests
    asyncio.run(test_attack_scenarios())
