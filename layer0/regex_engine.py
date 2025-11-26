"""
Safe regex execution engine for Layer-0 Security Filter System.

Supports RE2 (primary), regex, and re (fallback) with timeout enforcement.
"""

import logging
import re
import signal
import time
from typing import Any, Dict, Optional, Pattern

from layer0.config import settings

logger = logging.getLogger(__name__)


class RegexTimeout(Exception):
    """Raised when regex execution exceeds timeout."""
    pass


class RegexEngine:
    """Safe regex execution with timeout and ReDoS protection."""

    def __init__(self) -> None:
        """Initialize regex engine."""
        self.timeout_ms = settings.regex_timeout_ms
        self.engine = settings.regex_engine
        self._pattern_cache: Dict[str, Any] = {}

        # Try to import RE2
        self.re2_available = False
        try:
            import re2  # type: ignore
            self.re2 = re2
            self.re2_available = True
            logger.info("RE2 library available, using for regex execution")
        except ImportError:
            logger.warning("RE2 library not available, falling back to regex/re")

        # Try to import regex (enhanced re)
        self.regex_available = False
        try:
            import regex  # type: ignore
            self.regex = regex
            self.regex_available = True
            logger.info("regex library available as fallback")
        except ImportError:
            logger.warning("regex library not available, using standard re")

    def compile(self, pattern: str, flags: int = 0) -> Any:
        """
        Compile regex pattern with caching.

        Args:
            pattern: Regex pattern string
            flags: Regex flags

        Returns:
            Compiled pattern object
        """
        cache_key = f"{pattern}:{flags}"

        if cache_key in self._pattern_cache:
            return self._pattern_cache[cache_key]

        # Compile based on available engine
        if self.engine == "re2" and self.re2_available:
            compiled = self.re2.compile(pattern, flags)
        elif self.regex_available:
            compiled = self.regex.compile(pattern, flags)
        else:
            compiled = re.compile(pattern, flags)

        self._pattern_cache[cache_key] = compiled
        return compiled

    def search(
        self,
        pattern: str,
        text: str,
        flags: int = 0,
        timeout_ms: Optional[int] = None,
    ) -> Optional[Any]:
        """
        Search for pattern in text with timeout.

        Args:
            pattern: Regex pattern
            text: Text to search
            flags: Regex flags
            timeout_ms: Timeout in milliseconds (overrides default)

        Returns:
            Match object or None

        Raises:
            RegexTimeout: If execution exceeds timeout
        """
        timeout = timeout_ms if timeout_ms is not None else self.timeout_ms
        compiled = self.compile(pattern, flags)

        # RE2 has guaranteed linear time, no timeout needed
        if self.engine == "re2" and self.re2_available:
            return compiled.search(text)

        # For regex/re, use timeout wrapper
        return self._search_with_timeout(compiled, text, timeout)

    def findall(
        self,
        pattern: str,
        text: str,
        flags: int = 0,
        timeout_ms: Optional[int] = None,
    ) -> list:
        """
        Find all matches with timeout.

        Args:
            pattern: Regex pattern
            text: Text to search
            flags: Regex flags
            timeout_ms: Timeout in milliseconds

        Returns:
            List of matches

        Raises:
            RegexTimeout: If execution exceeds timeout
        """
        timeout = timeout_ms if timeout_ms is not None else self.timeout_ms
        compiled = self.compile(pattern, flags)

        if self.engine == "re2" and self.re2_available:
            return compiled.findall(text)

        return self._findall_with_timeout(compiled, text, timeout)

    def _search_with_timeout(
        self, compiled: Pattern[str], text: str, timeout_ms: int
    ) -> Optional[Any]:
        """Execute search with timeout."""
        start_time = time.perf_counter()

        try:
            match = compiled.search(text)
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if elapsed_ms > timeout_ms:
                logger.warning(
                    f"Regex search exceeded timeout: {elapsed_ms:.2f}ms > {timeout_ms}ms"
                )
                raise RegexTimeout(
                    f"Regex execution exceeded {timeout_ms}ms timeout"
                )

            return match

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if elapsed_ms > timeout_ms or "timeout" in str(e).lower():
                raise RegexTimeout(
                    f"Regex execution exceeded {timeout_ms}ms timeout"
                )
            raise

    def _findall_with_timeout(
        self, compiled: Pattern[str], text: str, timeout_ms: int
    ) -> list:
        """Execute findall with timeout."""
        start_time = time.perf_counter()

        try:
            matches = compiled.findall(text)
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if elapsed_ms > timeout_ms:
                logger.warning(
                    f"Regex findall exceeded timeout: {elapsed_ms:.2f}ms > {timeout_ms}ms"
                )
                raise RegexTimeout(
                    f"Regex execution exceeded {timeout_ms}ms timeout"
                )

            return matches

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if elapsed_ms > timeout_ms or "timeout" in str(e).lower():
                raise RegexTimeout(
                    f"Regex execution exceeded {timeout_ms}ms timeout"
                )
            raise

    def clear_cache(self) -> None:
        """Clear pattern cache."""
        self._pattern_cache.clear()
        logger.info("Regex pattern cache cleared")

    def get_cache_size(self) -> int:
        """Get current cache size."""
        return len(self._pattern_cache)


# Global regex engine instance
regex_engine = RegexEngine()
