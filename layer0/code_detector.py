"""
Code detection module for Layer-0 Security Filter System.

Deterministic code detection to bypass rule engine for legitimate code inputs.
"""

import re
from typing import Dict, Tuple

from layer0.config import settings


class CodeDetector:
    """Deterministic code detector using multiple heuristics."""

    # Programming language keywords
    LANGUAGE_KEYWORDS = {
        "python": {
            "def", "class", "import", "from", "return", "if", "else", "elif",
            "for", "while", "try", "except", "finally", "with", "as", "lambda",
            "yield", "async", "await", "raise", "assert", "pass", "break", "continue",
        },
        "javascript": {
            "function", "const", "let", "var", "return", "if", "else", "for",
            "while", "switch", "case", "break", "continue", "try", "catch",
            "finally", "async", "await", "class", "extends", "import", "export",
        },
        "java": {
            "public", "private", "protected", "class", "interface", "extends",
            "implements", "static", "final", "void", "return", "if", "else",
            "for", "while", "switch", "case", "try", "catch", "finally", "throw",
        },
        "sql": {
            "select", "from", "where", "insert", "update", "delete", "create",
            "drop", "alter", "table", "join", "inner", "outer", "left", "right",
            "group", "order", "by", "having", "limit", "offset",
        },
        "go": {
            "func", "package", "import", "type", "struct", "interface", "return",
            "if", "else", "for", "range", "switch", "case", "defer", "go",
            "chan", "select", "var", "const",
        },
        "rust": {
            "fn", "let", "mut", "const", "static", "struct", "enum", "impl",
            "trait", "type", "use", "mod", "pub", "if", "else", "match",
            "loop", "while", "for", "return", "break", "continue",
        },
    }

    # Fenced code block patterns
    FENCED_BLOCK_PATTERN = re.compile(
        r"```(?P<lang>\w+)?\s*\n(?P<code>.*?)```",
        re.DOTALL | re.MULTILINE,
    )

    # Indentation patterns (4+ spaces or tabs)
    INDENTATION_PATTERN = re.compile(r"^(?:    |\t)", re.MULTILINE)

    def __init__(self) -> None:
        """Initialize code detector."""
        self.enabled = settings.code_detection_enabled
        self.confidence_threshold = settings.code_confidence_threshold

    def detect(self, text: str) -> Tuple[bool, float, str]:
        """
        Detect if text is code.

        Args:
            text: Input text to analyze

        Returns:
            Tuple of (is_code, confidence, reason)
        """
        if not self.enabled:
            return False, 0.0, "code_detection_disabled"

        # Check for fenced code blocks
        if self._has_fenced_blocks(text):
            return True, 1.0, "fenced_code_block"

        # Calculate various code indicators
        indentation_score = self._calculate_indentation_score(text)
        token_score = self._calculate_token_score(text)
        keyword_score = self._calculate_keyword_score(text)

        # Weighted ensemble
        confidence = (
            0.4 * indentation_score +
            0.3 * token_score +
            0.3 * keyword_score
        )

        is_code = confidence >= self.confidence_threshold

        reason = self._get_detection_reason(
            indentation_score, token_score, keyword_score
        )

        return is_code, confidence, reason

    def _has_fenced_blocks(self, text: str) -> bool:
        """Check for fenced code blocks (```language)."""
        return bool(self.FENCED_BLOCK_PATTERN.search(text))

    def _calculate_indentation_score(self, text: str) -> float:
        """Calculate indentation score (0.0-1.0)."""
        lines = text.split("\n")
        if not lines:
            return 0.0

        indented_lines = len(self.INDENTATION_PATTERN.findall(text))
        total_lines = len([line for line in lines if line.strip()])

        if total_lines == 0:
            return 0.0

        ratio = indented_lines / total_lines

        # High indentation ratio suggests code
        if ratio >= 0.5:
            return 1.0
        elif ratio >= 0.3:
            return 0.7
        elif ratio >= 0.1:
            return 0.4
        else:
            return 0.0

    def _calculate_token_score(self, text: str) -> float:
        """Calculate token ratio score (0.0-1.0)."""
        # Count different character types
        alpha_count = sum(1 for c in text if c.isalpha())
        digit_count = sum(1 for c in text if c.isdigit())
        punct_count = sum(1 for c in text if c in "{}[]();:,.<>!@#$%^&*-+=|\\/?")
        total_chars = len(text.replace(" ", "").replace("\n", ""))

        if total_chars == 0:
            return 0.0

        # Code typically has high punctuation ratio
        punct_ratio = punct_count / total_chars

        if punct_ratio >= 0.3:
            return 1.0
        elif punct_ratio >= 0.2:
            return 0.7
        elif punct_ratio >= 0.1:
            return 0.4
        else:
            return 0.0

    def _calculate_keyword_score(self, text: str) -> float:
        """Calculate programming keyword score (0.0-1.0)."""
        text_lower = text.lower()
        words = re.findall(r"\b\w+\b", text_lower)

        if not words:
            return 0.0

        # Count keywords from all languages
        keyword_count = 0
        for lang_keywords in self.LANGUAGE_KEYWORDS.values():
            keyword_count += sum(1 for word in words if word in lang_keywords)

        keyword_ratio = keyword_count / len(words)

        if keyword_ratio >= 0.2:
            return 1.0
        elif keyword_ratio >= 0.1:
            return 0.7
        elif keyword_ratio >= 0.05:
            return 0.4
        else:
            return 0.0

    def _get_detection_reason(
        self, indentation: float, token: float, keyword: float
    ) -> str:
        """Get human-readable detection reason."""
        scores = {
            "indentation": indentation,
            "token_ratio": token,
            "keywords": keyword,
        }
        top_indicator = max(scores.items(), key=lambda x: x[1])
        return f"code_detected_{top_indicator[0]}"


# Global code detector instance
code_detector = CodeDetector()
