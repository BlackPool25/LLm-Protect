"""
Pattern matching utilities for security analysis.

Provides tools for detecting malicious patterns in text and data.
"""

import re
from typing import List, Dict, Tuple, Any
from collections import Counter


class PatternMatcher:
    """Pattern matcher for detecting suspicious sequences and patterns."""
    
    # Zero-width characters
    ZERO_WIDTH_CHARS = [
        '\u200B',  # Zero Width Space
        '\u200C',  # Zero Width Non-Joiner
        '\u200D',  # Zero Width Joiner
        '\u2060',  # Word Joiner
        '\uFEFF',  # Zero Width No-Break Space
    ]
    
    # Bidirectional override characters
    BIDI_CHARS = [
        '\u202A',  # Left-to-Right Embedding
        '\u202B',  # Right-to-Left Embedding
        '\u202C',  # Pop Directional Formatting
        '\u202D',  # Left-to-Right Override
        '\u202E',  # Right-to-Left Override
        '\u2066',  # Left-to-Right Isolate
        '\u2067',  # Right-to-Left Isolate
        '\u2068',  # First Strong Isolate
        '\u2069',  # Pop Directional Isolate
    ]
    
    # Homoglyph pairs (commonly confused characters)
    HOMOGLYPHS = {
        'a': ['а', 'ạ', 'ả', 'ã', 'à', 'á', 'â', 'ă', 'ầ', 'ấ'],  # Latin 'a' vs Cyrillic 'а'
        'e': ['е', 'ẹ', 'ẻ', 'ẽ', 'è', 'é', 'ê', 'ề', 'ế'],
        'o': ['о', 'ọ', 'ỏ', 'õ', 'ò', 'ó', 'ô', 'ồ', 'ố'],
        'i': ['і', 'ị', 'ỉ', 'ĩ', 'ì', 'í', 'î'],
        'c': ['с', 'ç', 'ċ', 'ĉ', 'č'],
        'p': ['р', 'ṗ', 'ṕ'],
        'x': ['х', 'ẋ'],
        'y': ['у', 'ỳ', 'ý', 'ŷ', 'ȳ'],
    }
    
    def __init__(self):
        """Initialize pattern matcher."""
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        # Common injection patterns
        self.sql_injection_pattern = re.compile(
            r"(\bunion\b.*\bselect\b|\bor\b.*=.*|'.*--|\bdrop\b.*\btable\b)",
            re.IGNORECASE
        )
        
        self.command_injection_pattern = re.compile(
            r"([;&|`$()]|\beval\b|\bexec\b|\bsystem\b)",
            re.IGNORECASE
        )
        
        # Prompt injection patterns
        self.prompt_injection_pattern = re.compile(
            r"(ignore (previous|all) (instructions|prompts)|"
            r"you are now|new (instructions|role)|"
            r"forget (everything|all)|disregard|override)",
            re.IGNORECASE
        )
    
    def detect_zero_width_chars(self, text: str) -> Dict[str, Any]:
        """
        Detect zero-width characters in text.
        
        Args:
            text: Input text
            
        Returns:
            Detection results with positions and counts
        """
        found_chars = []
        positions = []
        
        for i, char in enumerate(text):
            if char in self.ZERO_WIDTH_CHARS:
                found_chars.append(char)
                positions.append(i)
        
        if not found_chars:
            return {
                'detected': False,
                'count': 0,
                'positions': [],
                'chars': [],
                'density': 0.0
            }
        
        # Analyze distribution
        char_counts = Counter(found_chars)
        density = len(found_chars) / len(text) if text else 0
        
        return {
            'detected': True,
            'count': len(found_chars),
            'positions': positions,
            'chars': list(char_counts.keys()),
            'char_counts': dict(char_counts),
            'density': density,
            'suspicious': density > 0.01  # More than 1% is suspicious
        }
    
    def detect_bidi_chars(self, text: str) -> Dict[str, Any]:
        """
        Detect bidirectional override characters.
        
        Args:
            text: Input text
            
        Returns:
            Detection results
        """
        found_chars = []
        positions = []
        
        for i, char in enumerate(text):
            if char in self.BIDI_CHARS:
                found_chars.append(char)
                positions.append(i)
        
        if not found_chars:
            return {
                'detected': False,
                'count': 0,
                'positions': []
            }
        
        # Check for unmatched pairs
        unmatched = self._check_bidi_balance(text)
        
        return {
            'detected': True,
            'count': len(found_chars),
            'positions': positions,
            'unmatched': unmatched,
            'suspicious': unmatched > 0
        }
    
    def _check_bidi_balance(self, text: str) -> int:
        """Check if bidirectional formatting is balanced."""
        stack = []
        unmatched = 0
        
        push_chars = ['\u202A', '\u202B', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068']
        pop_chars = ['\u202C', '\u2069']
        
        for char in text:
            if char in push_chars:
                stack.append(char)
            elif char in pop_chars:
                if stack:
                    stack.pop()
                else:
                    unmatched += 1
        
        return unmatched + len(stack)
    
    def detect_homoglyphs(self, text: str) -> Dict[str, Any]:
        """
        Detect potential homoglyph substitution.
        
        Args:
            text: Input text
            
        Returns:
            Detection results
        """
        detected_homoglyphs = []
        
        for char in text:
            for base_char, variants in self.HOMOGLYPHS.items():
                if char in variants:
                    detected_homoglyphs.append({
                        'char': char,
                        'looks_like': base_char,
                        'unicode': f'U+{ord(char):04X}'
                    })
        
        return {
            'detected': len(detected_homoglyphs) > 0,
            'count': len(detected_homoglyphs),
            'homoglyphs': detected_homoglyphs,
            'suspicious': len(detected_homoglyphs) > 3
        }
    
    def detect_injection_patterns(self, text: str) -> Dict[str, Any]:
        """
        Detect common injection attack patterns.
        
        Args:
            text: Input text
            
        Returns:
            Detection results
        """
        results = {
            'sql_injection': bool(self.sql_injection_pattern.search(text)),
            'command_injection': bool(self.command_injection_pattern.search(text)),
            'prompt_injection': bool(self.prompt_injection_pattern.search(text)),
        }
        
        results['any_detected'] = any(results.values())
        
        return results
    
    def analyze_unicode_ranges(self, text: str) -> Dict[str, Any]:
        """
        Analyze Unicode ranges used in text.
        
        Args:
            text: Input text
            
        Returns:
            Analysis of Unicode ranges
        """
        range_counts = Counter()
        
        for char in text:
            code_point = ord(char)
            
            # Categorize by Unicode block
            if 0x0000 <= code_point <= 0x007F:
                range_counts['Basic Latin'] += 1
            elif 0x0080 <= code_point <= 0x00FF:
                range_counts['Latin-1 Supplement'] += 1
            elif 0x0400 <= code_point <= 0x04FF:
                range_counts['Cyrillic'] += 1
            elif 0x1F600 <= code_point <= 0x1F64F:
                range_counts['Emoticons'] += 1
            elif 0x1F300 <= code_point <= 0x1F5FF:
                range_counts['Miscellaneous Symbols'] += 1
            elif 0x2000 <= code_point <= 0x206F:
                range_counts['General Punctuation'] += 1
            else:
                range_counts['Other'] += 1
        
        total_chars = len(text)
        range_percentages = {
            range_name: (count / total_chars) * 100
            for range_name, count in range_counts.items()
        } if total_chars > 0 else {}
        
        # Suspicious if mixing too many scripts
        suspicious = len(range_counts) > 4
        
        return {
            'range_counts': dict(range_counts),
            'range_percentages': range_percentages,
            'num_ranges': len(range_counts),
            'suspicious_mixing': suspicious
        }
    
    def calculate_pattern_complexity(self, pattern_analysis: Dict[str, Any]) -> float:
        """
        Calculate overall pattern complexity score.
        
        Args:
            pattern_analysis: Results from pattern detection
            
        Returns:
            Complexity score (0-1)
        """
        score = 0.0
        
        # Weight different factors
        if 'detected' in pattern_analysis and pattern_analysis['detected']:
            score += 0.3
        
        if 'suspicious' in pattern_analysis and pattern_analysis['suspicious']:
            score += 0.4
        
        if 'density' in pattern_analysis:
            score += min(pattern_analysis['density'] * 10, 0.3)
        
        return min(score, 1.0)
