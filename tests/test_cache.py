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


class TestCacheEntryAdvanced:
    """Advanced tests for CacheEntry."""

    def test_age_seconds(self) -> None:
        """Test age_seconds property."""
        entry = CacheEntry(key="test", data="value", ttl_seconds=3600)
        time.sleep(0.1)
        age = entry.age_seconds
        assert age >= 0.1
        assert age < 1.0

    def test_expires_at(self) -> None:
        """Test expires_at property."""
        from datetime import datetime, timedelta

        entry = CacheEntry(key="test", data="value", ttl_seconds=3600)
        expected = entry.created_at + timedelta(seconds=3600)
        assert entry.expires_at == expected


class TestResponseCacheAdvanced:
    """Advanced tests for ResponseCache."""

    @pytest.fixture
    def cache_dir(self) -> Path:
        """Create temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_cache_dir_property(self, cache_dir: Path) -> None:
        """Test cache_dir property."""
        config = CacheConfig(enabled=True, directory=cache_dir)
        cache = ResponseCache(config)
        assert cache.cache_dir == cache_dir

    def test_enabled_property(self, cache_dir: Path) -> None:
        """Test enabled property."""
        config = CacheConfig(enabled=True, directory=cache_dir)
        cache = ResponseCache(config)
        assert cache.enabled is True

        config2 = CacheConfig(enabled=False, directory=cache_dir)
        cache2 = ResponseCache(config2)
        assert cache2.enabled is False

    def test_set_with_custom_ttl(self, cache_dir: Path) -> None:
        """Test set with custom TTL."""
        config = CacheConfig(enabled=True, directory=cache_dir, ttl_seconds=3600)
        cache = ResponseCache(config)

        # Set with custom TTL
        cache.set("key", "value", ttl_seconds=1)
        assert cache.get("key") == "value"

        time.sleep(1.1)
        assert cache.get("key") is None

    def test_get_missing_does_not_create_file(self, cache_dir: Path) -> None:
        """Test that getting missing key doesn't create file."""
        config = CacheConfig(enabled=True, directory=cache_dir)
        cache = ResponseCache(config)

        result = cache.get("nonexistent_key")
        assert result is None

        # No cache files should be created
        cache_files = list(cache_dir.glob("*.json"))
        assert len(cache_files) == 0

    def test_corrupted_cache_file(self, cache_dir: Path) -> None:
        """Test handling of corrupted cache file."""
        config = CacheConfig(enabled=True, directory=cache_dir)
        cache = ResponseCache(config)

        # Set a valid value first
        cache.set("key", "value")

        # Corrupt the file
        cache_file = list(cache_dir.glob("*.json"))[0]
        cache_file.write_text("not valid json {{{")

        # Getting the corrupted value should return None
        result = cache.get("key")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_or_fetch_disabled(self, cache_dir: Path) -> None:
        """Test get_or_fetch when cache is disabled."""
        config = CacheConfig(enabled=False, directory=cache_dir)
        cache = ResponseCache(config)

        call_count = 0

        async def fetch() -> str:
            nonlocal call_count
            call_count += 1
            return "fetched"

        # Should always call fetch when disabled
        result1 = await cache.get_or_fetch("key", fetch)
        assert result1 == "fetched"
        assert call_count == 1

        result2 = await cache.get_or_fetch("key", fetch)
        assert result2 == "fetched"
        assert call_count == 2  # Called again because cache is disabled

    def test_get_or_fetch_sync_disabled(self, cache_dir: Path) -> None:
        """Test get_or_fetch_sync when cache is disabled."""
        config = CacheConfig(enabled=False, directory=cache_dir)
        cache = ResponseCache(config)

        call_count = 0

        def fetch() -> str:
            nonlocal call_count
            call_count += 1
            return "fetched"

        result1 = cache.get_or_fetch_sync("key", fetch)
        assert result1 == "fetched"
        assert call_count == 1

        result2 = cache.get_or_fetch_sync("key", fetch)
        assert result2 == "fetched"
        assert call_count == 2  # Called again

    def test_default_config(self) -> None:
        """Test cache with default config."""
        cache = ResponseCache()
        assert cache.config is not None

    def test_delete_nonexistent(self, cache_dir: Path) -> None:
        """Test deleting nonexistent key."""
        config = CacheConfig(enabled=True, directory=cache_dir)
        cache = ResponseCache(config)

        result = cache.delete("nonexistent")
        assert result is False


class TestMemoryCacheAdvanced:
    """Advanced tests for MemoryCache."""

    def test_default_ttl(self) -> None:
        """Test default TTL."""
        cache = MemoryCache()  # Uses default TTL
        cache.set("key", "value")
        assert cache.get("key") == "value"

    def test_get_missing(self) -> None:
        """Test get missing key."""
        cache = MemoryCache()
        assert cache.get("missing") is None

    def test_delete(self) -> None:
        """Test delete."""
        cache = MemoryCache()
        cache.set("key", "value")

        result = cache.delete("key")
        assert result is True
        assert cache.get("key") is None

        result2 = cache.delete("key")
        assert result2 is False

    def test_custom_ttl_per_entry(self) -> None:
        """Test custom TTL per entry."""
        cache = MemoryCache(ttl_seconds=3600)  # Default 1 hour
        cache.set("short", "value", ttl_seconds=1)  # Override to 1 second
        cache.set("long", "value")  # Uses default

        time.sleep(1.1)
        assert cache.get("short") is None
        assert cache.get("long") == "value"


class TestCacheStatsAdvanced:
    """Advanced tests for CacheStats."""

    def test_writes_stat(self) -> None:
        """Test writes statistic."""
        stats = CacheStats()
        assert stats.writes == 0
        stats.writes = 10
        assert stats.writes == 10

    def test_record_hit(self) -> None:
        """Test record_hit convenience method if exists."""
        stats = CacheStats()
        # Just test the properties work correctly
        stats.hits += 1
        assert stats.hits == 1

    def test_total_requests_zero(self) -> None:
        """Test total_requests when no requests."""
        stats = CacheStats()
        assert stats.total_requests == 0
        assert stats.hit_rate == 0.0


class TestResponseCacheSizeLimit:
    """Tests for cache size limits."""

    @pytest.fixture
    def cache_dir(self) -> Path:
        """Create temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_get_size_bytes(self, cache_dir: Path) -> None:
        """Test get_size_bytes."""
        config = CacheConfig(enabled=True, directory=cache_dir)
        cache = ResponseCache(config)

        # Initially empty
        assert cache.get_size_bytes() == 0

        # Add some data
        cache.set("key1", "value1")
        size = cache.get_size_bytes()
        assert size > 0

    def test_get_size_mb(self, cache_dir: Path) -> None:
        """Test get_size_mb."""
        config = CacheConfig(enabled=True, directory=cache_dir)
        cache = ResponseCache(config)

        cache.set("key1", "value1")
        size_mb = cache.get_size_mb()
        assert size_mb >= 0
        assert size_mb < 1  # Should be tiny

    def test_get_size_nonexistent_dir(self) -> None:
        """Test get_size when directory doesn't exist."""
        config = CacheConfig(enabled=True, directory="/nonexistent/path/cache")
        cache = ResponseCache(config)

        assert cache.get_size_bytes() == 0
        assert cache.get_size_mb() == 0.0

    def test_clear_nonexistent_dir(self) -> None:
        """Test clear when directory doesn't exist."""
        config = CacheConfig(enabled=True, directory="/nonexistent/path/cache")
        cache = ResponseCache(config)

        result = cache.clear()
        assert result == 0

    def test_clear_expired_nonexistent_dir(self) -> None:
        """Test clear_expired when directory doesn't exist."""
        config = CacheConfig(enabled=True, directory="/nonexistent/path/cache")
        cache = ResponseCache(config)

        result = cache.clear_expired()
        assert result == 0

    def test_enforce_size_limit_under_limit(self, cache_dir: Path) -> None:
        """Test enforce_size_limit when under limit."""
        config = CacheConfig(enabled=True, directory=cache_dir, max_size_mb=100)
        cache = ResponseCache(config)

        cache.set("key1", "small data")
        result = cache.enforce_size_limit()
        assert result == 0

    def test_enforce_size_limit_over_limit(self, cache_dir: Path) -> None:
        """Test enforce_size_limit when over limit."""
        # Use max_size_mb=1 and fill with enough data to exceed it
        config = CacheConfig(enabled=True, directory=cache_dir, max_size_mb=1)
        cache = ResponseCache(config)

        # Add many large entries to exceed 1MB limit
        large_data = "x" * 100000  # 100KB per entry
        for i in range(20):  # 2MB total
            cache.set(f"key{i}", large_data)

        result = cache.enforce_size_limit()
        assert result > 0  # Some entries should be removed

    def test_enforce_size_limit_nonexistent_dir(self) -> None:
        """Test enforce_size_limit when directory doesn't exist."""
        config = CacheConfig(enabled=True, directory="/nonexistent/path/cache")
        cache = ResponseCache(config)

        result = cache.enforce_size_limit()
        assert result == 0

    def test_enforce_size_limit_with_corrupted_entries(self, cache_dir: Path) -> None:
        """Test enforce_size_limit with corrupted entries."""
        config = CacheConfig(enabled=True, directory=cache_dir, max_size_mb=1)
        cache = ResponseCache(config)

        # Add large entries to exceed limit
        large_data = "x" * 100000  # 100KB per entry
        for i in range(20):  # 2MB total
            cache.set(f"key{i}", large_data)

        # Corrupt one file
        cache_files = list(cache_dir.glob("*.json"))
        if cache_files:
            cache_files[0].write_text("corrupted json {{{")

        result = cache.enforce_size_limit()
        # Should handle corrupted entries gracefully and remove some
        assert isinstance(result, int)
        assert result > 0

    def test_clear_expired_with_corrupted_entries(self, cache_dir: Path) -> None:
        """Test clear_expired with corrupted entries."""
        config = CacheConfig(enabled=True, directory=cache_dir, ttl_seconds=1)
        cache = ResponseCache(config)

        # Add an entry
        cache.set("key", "value")

        # Corrupt the file
        cache_file = list(cache_dir.glob("*.json"))[0]
        cache_file.write_text("corrupted {{{")

        # Should remove corrupted entries
        result = cache.clear_expired()
        assert result >= 1


class TestCacheWriteError:
    """Tests for cache write errors."""

    def test_set_write_error(self) -> None:
        """Test set with write error raises CacheError."""
        from pulse.cache import CacheError
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmpdir:
            config = CacheConfig(enabled=True, directory=tmpdir)
            cache = ResponseCache(config)

            # Make the write fail
            with patch("builtins.open", side_effect=OSError("Disk full")):
                with pytest.raises(CacheError):
                    cache.set("key", "value")
