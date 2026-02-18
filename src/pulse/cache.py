"""Response caching layer for Pulse.

Provides efficient caching of GitHub API responses to reduce
API calls and improve response times.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, TypeVar

from pulse.config import CacheConfig

T = TypeVar("T")


class CacheError(Exception):
    """Cache operation error."""

    pass


class CacheEntry:
    """Represents a cached entry with metadata."""

    def __init__(
        self,
        key: str,
        data: Any,
        created_at: datetime | None = None,
        ttl_seconds: int = 3600,
    ) -> None:
        """Initialize cache entry.

        Args:
            key: Cache key.
            data: Cached data.
            created_at: When the entry was created.
            ttl_seconds: Time-to-live in seconds.
        """
        self.key = key
        self.data = data
        self.created_at = created_at or datetime.now()
        self.ttl_seconds = ttl_seconds

    @property
    def expires_at(self) -> datetime:
        """Get expiration time."""
        return self.created_at + timedelta(seconds=self.ttl_seconds)

    @property
    def is_expired(self) -> bool:
        """Check if entry is expired."""
        return datetime.now() > self.expires_at

    @property
    def age_seconds(self) -> float:
        """Get age in seconds."""
        return (datetime.now() - self.created_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "key": self.key,
            "data": self.data,
            "created_at": self.created_at.isoformat(),
            "ttl_seconds": self.ttl_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheEntry:
        """Deserialize from dictionary."""
        return cls(
            key=data["key"],
            data=data["data"],
            created_at=datetime.fromisoformat(data["created_at"]),
            ttl_seconds=data["ttl_seconds"],
        )


class ResponseCache:
    """File-based response cache with TTL support.

    Caches API responses to disk with automatic expiration and size limits.

    Example:
        >>> cache = ResponseCache(config.cache)
        >>> async with cache:
        ...     data = await cache.get_or_fetch(
        ...         "repos/myrepo",
        ...         lambda: api_client.get_repository("myrepo")
        ...     )
    """

    def __init__(self, config: CacheConfig | None = None) -> None:
        """Initialize response cache.

        Args:
            config: Cache configuration.
        """
        self.config = config or CacheConfig()
        self._cache_dir = Path(self.config.directory).expanduser()
        self._stats = CacheStats()
        self._initialized = False

    @property
    def enabled(self) -> bool:
        """Check if caching is enabled."""
        return self.config.enabled

    @property
    def cache_dir(self) -> Path:
        """Get cache directory."""
        return self._cache_dir

    @property
    def stats(self) -> CacheStats:
        """Get cache statistics."""
        return self._stats

    def _ensure_dir(self) -> None:
        """Ensure cache directory exists."""
        if not self._initialized:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._initialized = True

    def _key_to_path(self, key: str) -> Path:
        """Convert cache key to file path.

        Args:
            key: Cache key.

        Returns:
            Path to cache file.
        """
        # Hash the key for filesystem-safe name
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:32]
        return self._cache_dir / f"{key_hash}.json"

    def _serialize(self, entry: CacheEntry) -> str:
        """Serialize cache entry to JSON."""
        return json.dumps(entry.to_dict(), indent=2)

    def _deserialize(self, data: str) -> CacheEntry:
        """Deserialize JSON to cache entry."""
        return CacheEntry.from_dict(json.loads(data))

    def get(self, key: str) -> Any | None:
        """Get cached value.

        Args:
            key: Cache key.

        Returns:
            Cached data or None if not found/expired.
        """
        if not self.enabled:
            return None

        self._ensure_dir()
        path = self._key_to_path(key)

        if not path.exists():
            self._stats.misses += 1
            return None

        try:
            with open(path) as f:
                entry = self._deserialize(f.read())

            if entry.is_expired:
                self._stats.expirations += 1
                path.unlink(missing_ok=True)
                return None

            self._stats.hits += 1
            return entry.data

        except (json.JSONDecodeError, KeyError, OSError):
            self._stats.errors += 1
            path.unlink(missing_ok=True)
            return None

    def set(
        self,
        key: str,
        data: Any,
        ttl_seconds: int | None = None,
    ) -> None:
        """Set cached value.

        Args:
            key: Cache key.
            data: Data to cache.
            ttl_seconds: Optional TTL override.
        """
        if not self.enabled:
            return

        self._ensure_dir()
        path = self._key_to_path(key)

        entry = CacheEntry(
            key=key,
            data=data,
            ttl_seconds=ttl_seconds or self.config.ttl_seconds,
        )

        try:
            with open(path, "w") as f:
                f.write(self._serialize(entry))
            self._stats.writes += 1
        except OSError as e:
            self._stats.errors += 1
            raise CacheError(f"Failed to write cache: {e}") from e

    def delete(self, key: str) -> bool:
        """Delete cached value.

        Args:
            key: Cache key.

        Returns:
            True if entry was deleted.
        """
        path = self._key_to_path(key)
        if path.exists():
            path.unlink()
            return True
        return False

    def clear(self) -> int:
        """Clear all cached entries.

        Returns:
            Number of entries cleared.
        """
        if not self._cache_dir.exists():
            return 0

        count = 0
        for path in self._cache_dir.glob("*.json"):
            path.unlink()
            count += 1

        return count

    def clear_expired(self) -> int:
        """Clear expired entries.

        Returns:
            Number of entries cleared.
        """
        if not self._cache_dir.exists():
            return 0

        count = 0
        for path in self._cache_dir.glob("*.json"):
            try:
                with open(path) as f:
                    entry = self._deserialize(f.read())
                if entry.is_expired:
                    path.unlink()
                    count += 1
            except (json.JSONDecodeError, KeyError, OSError):
                path.unlink(missing_ok=True)
                count += 1

        return count

    def get_size_bytes(self) -> int:
        """Get total cache size in bytes."""
        if not self._cache_dir.exists():
            return 0

        return sum(f.stat().st_size for f in self._cache_dir.glob("*.json"))

    def get_size_mb(self) -> float:
        """Get total cache size in megabytes."""
        return self.get_size_bytes() / (1024 * 1024)

    def enforce_size_limit(self) -> int:
        """Enforce maximum cache size by removing oldest entries.

        Returns:
            Number of entries removed.
        """
        if not self._cache_dir.exists():
            return 0

        max_bytes = self.config.max_size_mb * 1024 * 1024
        current_size = self.get_size_bytes()

        if current_size <= max_bytes:
            return 0

        # Get entries sorted by creation time (oldest first)
        entries: list[tuple[Path, float]] = []
        for path in self._cache_dir.glob("*.json"):
            try:
                with open(path) as f:
                    entry = self._deserialize(f.read())
                entries.append((path, entry.created_at.timestamp()))
            except (json.JSONDecodeError, KeyError, OSError):
                # Invalid entry, add with oldest timestamp
                entries.append((path, 0))

        entries.sort(key=lambda x: x[1])

        # Remove oldest entries until under limit
        removed = 0
        for path, _ in entries:
            if current_size <= max_bytes:
                break
            size = path.stat().st_size
            path.unlink()
            current_size -= size
            removed += 1

        return removed

    async def get_or_fetch(
        self,
        key: str,
        fetch_fn: Callable[[], Any],
        ttl_seconds: int | None = None,
    ) -> Any:
        """Get cached value or fetch and cache.

        Args:
            key: Cache key.
            fetch_fn: Async function to fetch data if not cached.
            ttl_seconds: Optional TTL override.

        Returns:
            Cached or freshly fetched data.
        """
        # Check cache first
        cached = self.get(key)
        if cached is not None:
            return cached

        # Fetch fresh data
        data = await fetch_fn()

        # Cache the result
        self.set(key, data, ttl_seconds)

        return data

    def get_or_fetch_sync(
        self,
        key: str,
        fetch_fn: Callable[[], T],
        ttl_seconds: int | None = None,
    ) -> T:
        """Synchronous version of get_or_fetch.

        Args:
            key: Cache key.
            fetch_fn: Function to fetch data if not cached.
            ttl_seconds: Optional TTL override.

        Returns:
            Cached or freshly fetched data.
        """
        # Check cache first
        cached = self.get(key)
        if cached is not None:
            return cached

        # Fetch fresh data
        data = fetch_fn()

        # Cache the result
        self.set(key, data, ttl_seconds)

        return data

    def __enter__(self) -> ResponseCache:
        """Enter sync context."""
        self._ensure_dir()
        return self

    def __exit__(self, *args: Any) -> None:
        """Exit sync context - cleanup expired entries."""
        self.clear_expired()
        self.enforce_size_limit()

    async def __aenter__(self) -> ResponseCache:
        """Enter async context."""
        self._ensure_dir()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context - cleanup expired entries."""
        self.clear_expired()
        self.enforce_size_limit()


class CacheStats:
    """Cache statistics."""

    def __init__(self) -> None:
        """Initialize statistics."""
        self.hits = 0
        self.misses = 0
        self.writes = 0
        self.errors = 0
        self.expirations = 0

    @property
    def total_requests(self) -> int:
        """Get total cache requests."""
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        """Get cache hit rate (0.0-1.0)."""
        if self.total_requests == 0:
            return 0.0
        return self.hits / self.total_requests

    def reset(self) -> None:
        """Reset all statistics."""
        self.hits = 0
        self.misses = 0
        self.writes = 0
        self.errors = 0
        self.expirations = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "errors": self.errors,
            "expirations": self.expirations,
            "total_requests": self.total_requests,
            "hit_rate": round(self.hit_rate, 3),
        }


class MemoryCache:
    """Simple in-memory cache for session-level caching.

    Useful for caching data within a single scan session.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        """Initialize memory cache.

        Args:
            ttl_seconds: Default TTL for entries.
        """
        self.ttl_seconds = ttl_seconds
        self._data: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Any | None:
        """Get cached value."""
        if key not in self._data:
            return None

        value, expires_at = self._data[key]
        if time.time() > expires_at:
            del self._data[key]
            return None

        return value

    def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        """Set cached value."""
        ttl = ttl_seconds or self.ttl_seconds
        expires_at = time.time() + ttl
        self._data[key] = (value, expires_at)

    def delete(self, key: str) -> bool:
        """Delete cached value."""
        if key in self._data:
            del self._data[key]
            return True
        return False

    def clear(self) -> int:
        """Clear all entries."""
        count = len(self._data)
        self._data.clear()
        return count

    def clear_expired(self) -> int:
        """Clear expired entries."""
        now = time.time()
        expired = [k for k, (_, exp) in self._data.items() if now > exp]
        for key in expired:
            del self._data[key]
        return len(expired)

    def __len__(self) -> int:
        """Get number of entries."""
        return len(self._data)

    def __contains__(self, key: str) -> bool:
        """Check if key exists and is valid."""
        return self.get(key) is not None
