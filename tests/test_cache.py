"""Tests for cache module."""

import tempfile
import time
from pathlib import Path

import pytest

from pulse.cache import (
    CacheEntry,
    CacheStats,
    MemoryCache,
    ResponseCache,
)
from pulse.config import CacheConfig


class TestCacheEntry:
    """Tests for CacheEntry."""

    def test_create_entry(self) -> None:
        """Test creating a cache entry."""
        entry = CacheEntry(
            key="test_key",
            data={"foo": "bar"},
            ttl_seconds=3600,
        )

        assert entry.key == "test_key"
        assert entry.data == {"foo": "bar"}
        assert entry.ttl_seconds == 3600
        assert not entry.is_expired

    def test_expiration(self) -> None:
        """Test entry expiration."""
        entry = CacheEntry(
            key="test",
            data="value",
            ttl_seconds=1,
        )

        assert not entry.is_expired
        time.sleep(1.1)
        assert entry.is_expired

    def test_serialization(self) -> None:
        """Test entry serialization."""
        entry = CacheEntry(
            key="test",
            data={"nested": [1, 2, 3]},
            ttl_seconds=3600,
        )

        data = entry.to_dict()
        restored = CacheEntry.from_dict(data)

        assert restored.key == entry.key
        assert restored.data == entry.data
        assert restored.ttl_seconds == entry.ttl_seconds


class TestResponseCache:
    """Tests for ResponseCache."""

    @pytest.fixture
    def cache_dir(self) -> Path:
        """Create temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def cache(self, cache_dir: Path) -> ResponseCache:
        """Create cache instance."""
        config = CacheConfig(
            enabled=True,
            directory=cache_dir,
            ttl_seconds=3600,
            max_size_mb=10,
        )
        return ResponseCache(config)

    def test_set_and_get(self, cache: ResponseCache) -> None:
        """Test basic set and get."""
        cache.set("key1", {"data": "value1"})
        result = cache.get("key1")

        assert result == {"data": "value1"}

    def test_get_missing(self, cache: ResponseCache) -> None:
        """Test get for missing key."""
        result = cache.get("nonexistent")
        assert result is None

    def test_expiration(self, cache_dir: Path) -> None:
        """Test cache expiration."""
        config = CacheConfig(
            enabled=True,
            directory=cache_dir,
            ttl_seconds=1,
        )
        cache = ResponseCache(config)

        cache.set("key", "value")
        assert cache.get("key") == "value"

        time.sleep(1.1)
        assert cache.get("key") is None

    def test_delete(self, cache: ResponseCache) -> None:
        """Test delete."""
        cache.set("key", "value")
        assert cache.get("key") == "value"

        assert cache.delete("key") is True
        assert cache.get("key") is None
        assert cache.delete("key") is False

    def test_clear(self, cache: ResponseCache) -> None:
        """Test clear all."""
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        cleared = cache.clear()
        assert cleared == 3
        assert cache.get("key1") is None

    def test_clear_expired(self, cache_dir: Path) -> None:
        """Test clearing expired entries."""
        config = CacheConfig(
            enabled=True,
            directory=cache_dir,
            ttl_seconds=3600,
        )
        cache = ResponseCache(config)

        # Add normal entry
        cache.set("fresh", "value")

        # Add expired entry
        cache.set("stale", "old", ttl_seconds=1)
        time.sleep(1.1)

        cleared = cache.clear_expired()
        assert cleared == 1
        assert cache.get("fresh") == "value"

    def test_disabled_cache(self, cache_dir: Path) -> None:
        """Test cache when disabled."""
        config = CacheConfig(enabled=False, directory=cache_dir)
        cache = ResponseCache(config)

        cache.set("key", "value")
        assert cache.get("key") is None

    def test_stats(self, cache: ResponseCache) -> None:
        """Test cache statistics."""
        cache.set("key", "value")
        cache.get("key")  # Hit
        cache.get("missing")  # Miss

        assert cache.stats.hits == 1
        assert cache.stats.misses == 1
        assert cache.stats.writes == 1
        assert cache.stats.hit_rate == 0.5

    def test_get_or_fetch_sync(self, cache: ResponseCache) -> None:
        """Test synchronous get or fetch."""
        call_count = 0

        def fetch() -> str:
            nonlocal call_count
            call_count += 1
            return "fetched_value"

        # First call - fetches
        result1 = cache.get_or_fetch_sync("key", fetch)
        assert result1 == "fetched_value"
        assert call_count == 1

        # Second call - from cache
        result2 = cache.get_or_fetch_sync("key", fetch)
        assert result2 == "fetched_value"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_get_or_fetch_async(self, cache: ResponseCache) -> None:
        """Test async get or fetch."""
        call_count = 0

        async def fetch() -> str:
            nonlocal call_count
            call_count += 1
            return "async_value"

        result1 = await cache.get_or_fetch("key", fetch)
        assert result1 == "async_value"
        assert call_count == 1

        result2 = await cache.get_or_fetch("key", fetch)
        assert result2 == "async_value"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_context_manager(self, cache: ResponseCache) -> None:
        """Test async context manager."""
        async with cache as c:
            c.set("key", "value")
            assert c.get("key") == "value"


class TestCacheStats:
    """Tests for CacheStats."""

    def test_initial_stats(self) -> None:
        """Test initial statistics."""
        stats = CacheStats()

        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.hit_rate == 0.0

    def test_hit_rate(self) -> None:
        """Test hit rate calculation."""
        stats = CacheStats()
        stats.hits = 7
        stats.misses = 3

        assert stats.total_requests == 10
        assert stats.hit_rate == 0.7

    def test_reset(self) -> None:
        """Test reset."""
        stats = CacheStats()
        stats.hits = 100
        stats.misses = 50

        stats.reset()

        assert stats.hits == 0
        assert stats.misses == 0


class TestMemoryCache:
    """Tests for MemoryCache."""

    def test_set_and_get(self) -> None:
        """Test basic set and get."""
        cache = MemoryCache()
        cache.set("key", {"data": 123})

        assert cache.get("key") == {"data": 123}

    def test_expiration(self) -> None:
        """Test entry expiration."""
        cache = MemoryCache(ttl_seconds=1)
        cache.set("key", "value")

        assert cache.get("key") == "value"
        time.sleep(1.1)
        assert cache.get("key") is None

    def test_contains(self) -> None:
        """Test contains check."""
        cache = MemoryCache()
        cache.set("exists", "value")

        assert "exists" in cache
        assert "missing" not in cache

    def test_clear(self) -> None:
        """Test clear."""
        cache = MemoryCache()
        cache.set("a", 1)
        cache.set("b", 2)

        assert len(cache) == 2
        cleared = cache.clear()
        assert cleared == 2
        assert len(cache) == 0

    def test_clear_expired(self) -> None:
        """Test clearing expired entries."""
        cache = MemoryCache()
        cache.set("fresh", "value", ttl_seconds=3600)
        cache.set("stale", "old", ttl_seconds=1)

        time.sleep(1.1)
        cleared = cache.clear_expired()

        assert cleared == 1
        assert len(cache) == 1
        assert cache.get("fresh") == "value"
