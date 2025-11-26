"""
Text normalization pipeline for Layer-0 Security Filter System.

Multi-stage normalization to defeat obfuscation attacks:
1. Unicode NFKC normalization
2. Zero-width character removal
3. RTL/LTR marker removal
4. Whitespace collapse
5. Homoglyph-to-ASCII folding
6. Emoji handling
7. Base64 blob stripping
8. PDF artifact removal
9. Separator replacement
10. Control character removal
"""

import base64
import re
import unicodedata
from typing import List

from layer0.config import settings


class Normalizer:
    """Multi-stage text normalization pipeline."""

    # Zero-width and invisible characters
    ZERO_WIDTH_CHARS = [
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE
        "\u2060",  # WORD JOINER
        "\u180e",  # MONGOLIAN VOWEL SEPARATOR
    ]

    # Bidi control characters
    BIDI_CHARS = [
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
    ]

    # Common homoglyphs (Cyrillic/Greek -> ASCII)
    HOMOGLYPH_MAP = {
        # Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
        "Р": "P", "С": "C", "Т": "T", "Х": "X",
        # Greek
        "α": "a", "β": "b", "γ": "g", "δ": "d", "ε": "e", "ζ": "z", "η": "h",
        "θ": "th", "ι": "i", "κ": "k", "λ": "l", "μ": "m", "ν": "n", "ξ": "x",
        "ο": "o", "π": "p", "ρ": "r", "σ": "s", "τ": "t", "υ": "u", "φ": "f",
        "χ": "ch", "ψ": "ps", "ω": "o",
        "Α": "A", "Β": "B", "Γ": "G", "Δ": "D", "Ε": "E", "Ζ": "Z", "Η": "H",
        "Θ": "TH", "Ι": "I", "Κ": "K", "Λ": "L", "Μ": "M", "Ν": "N", "Ξ": "X",
        "Ο": "O", "Π": "P", "Ρ": "R", "Σ": "S", "Τ": "T", "Υ": "U", "Φ": "F",
        "Χ": "CH", "Ψ": "PS", "Ω": "O",
    }

    # Various separator characters
    SEPARATORS = [
        "\u2022",  # BULLET
        "\u2023",  # TRIANGULAR BULLET
        "\u2043",  # HYPHEN BULLET
        "\u204c",  # BLACK LEFTWARDS BULLET
        "\u204d",  # BLACK RIGHTWARDS BULLET
        "\u2212",  # MINUS SIGN
        "\u2013",  # EN DASH
        "\u2014",  # EM DASH
        "\u2015",  # HORIZONTAL BAR
    ]

    def __init__(self) -> None:
        """Initialize normalizer with configuration."""
        self.disabled_steps = set(settings.disabled_normalization_steps)
        self.enabled = settings.normalization_enabled

    def normalize(self, text: str) -> str:
        """
        Apply all normalization steps.

        Args:
            text: Input text to normalize

        Returns:
            Normalized text
        """
        if not self.enabled:
            return text

        # Apply each step in sequence
        text = self._step_1_unicode_nfkc(text)
        text = self._step_2_remove_zero_width(text)
        text = self._step_3_remove_bidi(text)
        text = self._step_4_collapse_whitespace(text)
        text = self._step_5_fold_homoglyphs(text)
        text = self._step_6_handle_emoji(text)
        text = self._step_7_strip_base64(text)
        text = self._step_8_remove_pdf_artifacts(text)
        text = self._step_9_replace_separators(text)
        text = self._step_10_remove_control_chars(text)

        return text

    def _step_1_unicode_nfkc(self, text: str) -> str:
        """Step 1: Unicode NFKC normalization."""
        if "unicode_nfkc" in self.disabled_steps:
            return text
        return unicodedata.normalize("NFKC", text)

    def _step_2_remove_zero_width(self, text: str) -> str:
        """Step 2: Remove zero-width characters."""
        if "zero_width" in self.disabled_steps:
            return text
        for char in self.ZERO_WIDTH_CHARS:
            text = text.replace(char, "")
        return text

    def _step_3_remove_bidi(self, text: str) -> str:
        """Step 3: Remove RTL/LTR markers."""
        if "bidi" in self.disabled_steps:
            return text
        for char in self.BIDI_CHARS:
            text = text.replace(char, "")
        return text

    def _step_4_collapse_whitespace(self, text: str) -> str:
        """Step 4: Collapse whitespace."""
        if "whitespace" in self.disabled_steps:
            return text
        # Replace all whitespace sequences with single space
        return re.sub(r"\s+", " ", text).strip()

    def _step_5_fold_homoglyphs(self, text: str) -> str:
        """Step 5: Fold homoglyphs to ASCII."""
        if "homoglyphs" in self.disabled_steps:
            return text
        for homoglyph, ascii_char in self.HOMOGLYPH_MAP.items():
            text = text.replace(homoglyph, ascii_char)
        return text

    def _step_6_handle_emoji(self, text: str) -> str:
        """Step 6: Handle emoji (strip or replace with space)."""
        if "emoji" in self.disabled_steps:
            return text
        # Remove emoji using Unicode ranges
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map symbols
            "\U0001F1E0-\U0001F1FF"  # flags (iOS)
            "\U00002702-\U000027B0"
            "\U000024C2-\U0001F251"
            "]+",
            flags=re.UNICODE,
        )
        return emoji_pattern.sub(" ", text)

    def _step_7_strip_base64(self, text: str) -> str:
        """Step 7: Strip Base64 blobs."""
        if "base64" in self.disabled_steps:
            return text
        # Detect and remove long Base64-like strings (50+ chars)
        base64_pattern = re.compile(r"[A-Za-z0-9+/]{50,}={0,2}")
        return base64_pattern.sub("[BASE64_REMOVED]", text)

    def _step_8_remove_pdf_artifacts(self, text: str) -> str:
        """Step 8: Remove PDF artifacts (broken hyphenation, extra newlines)."""
        if "pdf_artifacts" in self.disabled_steps:
            return text
        # Remove hyphenation at line breaks
        text = re.sub(r"-\s*\n\s*", "", text)
        # Collapse multiple newlines
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text

    def _step_9_replace_separators(self, text: str) -> str:
        """Step 9: Replace various separators with standard ones."""
        if "separators" in self.disabled_steps:
            return text
        for sep in self.SEPARATORS:
            text = text.replace(sep, "-")
        return text

    def _step_10_remove_control_chars(self, text: str) -> str:
        """Step 10: Remove control characters."""
        if "control_chars" in self.disabled_steps:
            return text
        # Remove control characters except newline, tab, carriage return
        return "".join(
            char for char in text
            if unicodedata.category(char)[0] != "C" or char in "\n\t\r"
        )


# Global normalizer instance
normalizer = Normalizer()
