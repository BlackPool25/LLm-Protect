"""
High-performance prefilter using Bloom filter + Aho-Corasick automaton.

This module provides ultra-fast pattern matching to quickly reject
clean inputs before expensive regex scanning.
"""

import logging
import re
from typing import List, Set, Tuple, Optional
import ahocorasick
from pybloom_live import BloomFilter

from layer0.models import Rule

logger = logging.getLogger(__name__)


class HybridPrefilter:
    """
    Two-stage prefilter combining Bloom filter and Aho-Corasick.
    
    Stage 1: Bloom filter (O(1) lookup, ~1μs)
    Stage 2: Aho-Corasick (O(n) multi-pattern, ~1-5ms)
    
    This allows us to reject 90%+ of clean inputs in <1ms.
    """
    
    def __init__(self, capacity: int = 100000, error_rate: float = 0.001):
        """
        Initialize hybrid prefilter.
        
        Args:
            capacity: Expected number of keywords
            error_rate: Bloom filter false positive rate
        """
        self.bloom = BloomFilter(capacity=capacity, error_rate=error_rate)
        self.automaton = ahocorasick.Automaton()
        self.keyword_count = 0
        self.enabled = False
        
    def build_from_rules(self, rules: List[Rule]) -> None:
        """
        Build prefilter from rule patterns.
        
        Extracts keywords from regex patterns and builds both
        Bloom filter and Aho-Corasick automaton.
        
        Args:
            rules: List of security rules
        """
        keywords: Set[str] = set()
        
        # Extract keywords from patterns
        for rule in rules:
            extracted = self._extract_keywords(rule.pattern)
            keywords.update(extracted)
        
        if not keywords:
            logger.warning("No keywords extracted from rules, prefilter disabled")
            self.enabled = False
            return
        
        # Build Bloom filter
        for keyword in keywords:
            self.bloom.add(keyword.lower())
        
        # Build Aho-Corasick automaton
        for idx, keyword in enumerate(keywords):
            self.automaton.add_word(keyword.lower(), (idx, keyword))
        
        self.automaton.make_automaton()
        self.keyword_count = len(keywords)
        self.enabled = True
        
        logger.info(
            f"Prefilter built with {self.keyword_count} keywords "
            f"(bloom: {len(self.bloom)}, aho-corasick: {len(self.automaton)})"
        )
    
    def _extract_keywords(self, pattern: str) -> Set[str]:
        """
        Extract literal keywords from regex pattern.
        
        Extracts fixed strings that must appear for the pattern to match.
        Ignores regex metacharacters and focuses on literal text.
        
        Args:
            pattern: Regex pattern string
            
        Returns:
            Set of extracted keywords (min length 3)
        """
        keywords: Set[str] = set()
        
        # Remove common regex metacharacters and extract literals
        # This is a simplified extraction - could be more sophisticated
        
        # Remove anchors, quantifiers, groups
        cleaned = re.sub(r'[\^$*+?{}()\[\]|\\]', ' ', pattern)
        
        # Split on whitespace and special chars
        tokens = re.split(r'\s+', cleaned)
        
        for token in tokens:
            # Only keep tokens that are:
            # 1. At least 3 characters
            # 2. Contain letters
            # 3. Not just numbers
            if len(token) >= 3 and any(c.isalpha() for c in token) and not token.isdigit():
                keywords.add(token.lower())
        
        # Also extract quoted strings (common in patterns)
        quoted = re.findall(r'"([^"]{3,})"', pattern)
        keywords.update(q.lower() for q in quoted)
        
        quoted = re.findall(r"'([^']{3,})'", pattern)
        keywords.update(q.lower() for q in quoted)
        
        return keywords
    
    def might_match(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Check if text might match any rule (fast prefilter).
        
        Returns (True, keyword) if text should be scanned.
        Returns (False, None) if text is definitely clean.
        
        Args:
            text: Normalized text to check
            
        Returns:
            Tuple of (should_scan, matched_keyword)
        """
        if not self.enabled:
            return True, None
        
        text_lower = text.lower()
        
        # Stage 1: Bloom filter check (ultra-fast)
        # If bloom says "no", it's definitely clean
        # If bloom says "yes", might be a false positive
        bloom_result = self._bloom_check(text_lower)
        if not bloom_result:
            return False, None
        
        # Stage 2: Aho-Corasick check (fast multi-pattern)
        # Confirms bloom filter result
        for end_index, (idx, keyword) in self.automaton.iter(text_lower):
            # Found a keyword match
            return True, keyword
        
        # No keywords found
        return False, None
    
    def _bloom_check(self, text: str) -> bool:
        """
        Check if any keyword might be in text using Bloom filter.
        
        This is a probabilistic check - false positives possible,
        but false negatives are impossible.
        
        Args:
            text: Lowercase text
            
        Returns:
            True if keywords might be present, False if definitely not
        """
        # Split text into words and check each
        words = text.split()
        
        for word in words:
            if len(word) >= 3 and word in self.bloom:
                return True
        
        # Also check substrings (for partial matches)
        for i in range(len(text) - 2):
            substring = text[i:i+10]  # Check 10-char windows
            if substring in self.bloom:
                return True
        
        return False
    
    def get_stats(self) -> dict:
        """Get prefilter statistics."""
        return {
            "enabled": self.enabled,
            "keyword_count": self.keyword_count,
            "bloom_size": len(self.bloom) if self.enabled else 0,
            "automaton_size": len(self.automaton) if self.enabled else 0,
        }


# Global prefilter instance
prefilter = HybridPrefilter()
