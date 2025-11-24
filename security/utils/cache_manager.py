"""
Cache manager for security analysis results.

Provides LRU caching with TTL for expensive security analyses.
"""

import time
import hashlib
from typing import Any, Callable, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CacheEntry:
    """Cache entry with value and metadata."""
    value: Any
    timestamp: float
    access_count: int = 0
    last_access: float = 0.0


class SecurityAnalysisCache:
    """
    LRU cache with TTL for security analysis results.
    
    Caches analysis results based on content hash to avoid
    redundant expensive operations.
    """
    
    def __init__(self, max_size: int = 10000, ttl: int = 3600):
        """
        Initialize cache.
        
        Args:
            max_size: Maximum number of entries
            ttl: Time-to-live in seconds
        """
        self.cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.ttl = ttl
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0,
        }
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found/expired
        """
        now = time.time()
        
        if key not in self.cache:
            self.stats['misses'] += 1
            return None
        
        entry = self.cache[key]
        
        # Check if expired
        if now - entry.timestamp > self.ttl:
            del self.cache[key]
            self.stats['expirations'] += 1
            self.stats['misses'] += 1
            return None
        
        # Update access metadata
        entry.access_count += 1
        entry.last_access = now
        
        self.stats['hits'] += 1
        return entry.value
    
    def set(self, key: str, value: Any) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        now = time.time()
        
        # Evict if necessary
        if len(self.cache) >= self.max_size and key not in self.cache:
            self._evict_lru()
        
        self.cache[key] = CacheEntry(
            value=value,
            timestamp=now,
            access_count=1,
            last_access=now
        )
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self.cache:
            return
        
        # Find LRU entry
        lru_key = min(
            self.cache.keys(),
            key=lambda k: self.cache[k].last_access
        )
        
        del self.cache[lru_key]
        self.stats['evictions'] += 1
    
    async def get_or_compute(
        self,
        key: str,
        compute_fn: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Get from cache or compute if not cached.
        
        Args:
            key: Cache key
            compute_fn: Function to compute value if not cached
            *args: Arguments for compute_fn
            **kwargs: Keyword arguments for compute_fn
            
        Returns:
            Cached or computed value
        """
        # Try cache first
        cached = self.get(key)
        if cached is not None:
            return cached
        
        # Compute value
        if asyncio.iscoroutinefunction(compute_fn):
            value = await compute_fn(*args, **kwargs)
        else:
            value = compute_fn(*args, **kwargs)
        
        # Cache result
        self.set(key, value)
        
        return value
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()
    
    def clear_expired(self) -> int:
        """
        Clear expired entries.
        
        Returns:
            Number of entries cleared
        """
        now = time.time()
        expired_keys = [
            key for key, entry in self.cache.items()
            if now - entry.timestamp > self.ttl
        ]
        
        for key in expired_keys:
            del self.cache[key]
        
        count = len(expired_keys)
        self.stats['expirations'] += count
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = self.stats['hits'] / total_requests if total_requests > 0 else 0
        
        return {
            **self.stats,
            'current_size': len(self.cache),
            'max_size': self.max_size,
            'hit_rate': hit_rate,
            'ttl': self.ttl,
        }
    
    @staticmethod
    def generate_content_hash(content: Any) -> str:
        """
        Generate hash key for content.
        
        Args:
            content: Content to hash (string, bytes, etc.)
            
        Returns:
            Hex digest of SHA256 hash
        """
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        elif isinstance(content, bytes):
            content_bytes = content
        else:
            content_bytes = str(content).encode('utf-8')
        
        return hashlib.sha256(content_bytes).hexdigest()


# Global cache instance
_global_cache: Optional[SecurityAnalysisCache] = None


def get_global_cache() -> SecurityAnalysisCache:
    """Get or create global cache instance."""
    global _global_cache
    if _global_cache is None:
        _global_cache = SecurityAnalysisCache()
    return _global_cache


# Import asyncio at the end to avoid circular imports
import asyncio
