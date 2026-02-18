"""Tests for Pulse ecosystem monitor."""

import pytest

from pulse.config import PulseConfig
from pulse.models import HealthStatus
from pulse.monitor import EcosystemMonitor


class TestEcosystemMonitor:
    """Tests for EcosystemMonitor."""

    def test_init_with_config(self) -> None:
        """Test initializing with config."""
        config = PulseConfig()
        monitor = EcosystemMonitor(config)

        assert monitor.organization == "sebastienrousseau"

    def test_init_with_org_override(self) -> None:
        """Test initializing with org override."""
        config = PulseConfig()
        monitor = EcosystemMonitor(config, org="other-org")

        assert monitor.organization == "other-org"

    def test_summary_initially_none(self) -> None:
        """Test summary is None before scan."""
        monitor = EcosystemMonitor()
        assert monitor.summary is None

    def test_get_critical_repos_empty(self) -> None:
        """Test get_critical_repos with no scan."""
        monitor = EcosystemMonitor()
        assert monitor.get_critical_repos() == []

    def test_get_repos_needing_attention_empty(self) -> None:
        """Test get_repos_needing_attention with no scan."""
        monitor = EcosystemMonitor()
        assert monitor.get_repos_needing_attention() == []

    def test_get_vulnerable_repos_empty(self) -> None:
        """Test get_vulnerable_repos with no scan."""
        monitor = EcosystemMonitor()
        assert monitor.get_vulnerable_repos() == []

    def test_get_failing_builds_empty(self) -> None:
        """Test get_failing_builds with no scan."""
        monitor = EcosystemMonitor()
        assert monitor.get_failing_builds() == []

    def test_get_stale_repos_empty(self) -> None:
        """Test get_stale_repos with no scan."""
        monitor = EcosystemMonitor()
        assert monitor.get_stale_repos() == []

    def test_should_include_repo(self) -> None:
        """Test repository filtering logic."""
        monitor = EcosystemMonitor()

        # Regular repo should be included
        repo_data = {
            "name": "test-repo",
            "archived": False,
            "fork": False,
            "private": False,
            "language": "Rust",
        }
        assert monitor._should_include_repo(repo_data) is True

    def test_should_exclude_archived(self) -> None:
        """Test archived repo exclusion."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.include_archived = False

        repo_data = {
            "name": "old-repo",
            "archived": True,
            "fork": False,
            "private": False,
        }
        assert monitor._should_include_repo(repo_data) is False

    def test_should_exclude_forks(self) -> None:
        """Test fork exclusion."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.include_forks = False

        repo_data = {
            "name": "forked-repo",
            "archived": False,
            "fork": True,
            "private": False,
        }
        assert monitor._should_include_repo(repo_data) is False

    def test_should_include_forks_when_enabled(self) -> None:
        """Test fork inclusion when enabled."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.include_forks = True

        repo_data = {
            "name": "forked-repo",
            "archived": False,
            "fork": True,
            "private": False,
        }
        assert monitor._should_include_repo(repo_data) is True

    def test_progress_callback(self) -> None:
        """Test progress callback setting."""
        monitor = EcosystemMonitor()
        called = []

        def callback(repo: str, current: int, total: int) -> None:
            called.append((repo, current, total))

        monitor.set_progress_callback(callback)
        monitor._report_progress("test-repo", 1, 10)

        assert called == [("test-repo", 1, 10)]


class TestEcosystemMonitorAsync:
    """Async tests for EcosystemMonitor."""

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Test async context manager."""
        async with EcosystemMonitor() as monitor:
            assert monitor is not None

    @pytest.mark.asyncio
    async def test_close(self) -> None:
        """Test closing monitor."""
        monitor = EcosystemMonitor()
        await monitor.close()
        # Should not raise
