"""Tests for Pulse ecosystem monitor."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pulse.config import PulseConfig
from pulse.github import GitHubAPIError, RateLimitExceeded
from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    Language,
    RepoHealth,
    RepoMetrics,
    VulnerabilityReport,
)
from pulse.monitor import EcosystemMonitor, MonitorError, run_scan


class TestMonitorError:
    """Tests for MonitorError."""

    def test_monitor_error(self) -> None:
        """Test MonitorError creation."""
        error = MonitorError("Test error")
        assert str(error) == "Test error"


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

    @pytest.mark.asyncio
    async def test_get_client(self) -> None:
        """Test _get_client creates client."""
        monitor = EcosystemMonitor()
        client = await monitor._get_client()
        assert client is not None
        await monitor.close()


class TestEcosystemMonitorFiltering:
    """Tests for repository filtering."""

    def test_should_exclude_private(self) -> None:
        """Test private repo exclusion."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.include_private = False

        repo_data = {
            "name": "private-repo",
            "archived": False,
            "fork": False,
            "private": True,
        }
        assert monitor._should_include_repo(repo_data) is False

    def test_should_include_private_when_enabled(self) -> None:
        """Test private repo inclusion when enabled."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.include_private = True

        repo_data = {
            "name": "private-repo",
            "archived": False,
            "fork": False,
            "private": True,
        }
        assert monitor._should_include_repo(repo_data) is True

    def test_should_filter_by_language(self) -> None:
        """Test language filtering."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.languages = ["rust", "python"]

        rust_repo = {"name": "rust-repo", "language": "Rust", "archived": False, "fork": False, "private": False}
        python_repo = {"name": "py-repo", "language": "Python", "archived": False, "fork": False, "private": False}
        go_repo = {"name": "go-repo", "language": "Go", "archived": False, "fork": False, "private": False}

        assert monitor._should_include_repo(rust_repo) is True
        assert monitor._should_include_repo(python_repo) is True
        assert monitor._should_include_repo(go_repo) is False

    def test_should_include_no_language(self) -> None:
        """Test repo with no language passes filter."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.languages = ["rust"]

        repo_data = {"name": "repo", "language": None, "archived": False, "fork": False, "private": False}
        assert monitor._should_include_repo(repo_data) is True

    def test_should_include_archived_when_enabled(self) -> None:
        """Test archived inclusion when enabled."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.include_archived = True

        repo_data = {"name": "archived-repo", "archived": True, "fork": False, "private": False}
        assert monitor._should_include_repo(repo_data) is True


class TestEcosystemMonitorScan:
    """Tests for scan operations."""

    @pytest.fixture
    def mock_repos(self) -> list[dict]:
        """Create mock repository data."""
        return [
            {
                "name": "repo1",
                "full_name": "org/repo1",
                "html_url": "https://github.com/org/repo1",
                "archived": False,
                "fork": False,
                "private": False,
                "language": "Python",
            },
            {
                "name": "repo2",
                "full_name": "org/repo2",
                "html_url": "https://github.com/org/repo2",
                "archived": False,
                "fork": False,
                "private": False,
                "language": "Rust",
            },
        ]

    @pytest.fixture
    def mock_health(self) -> RepoHealth:
        """Create mock repo health."""
        return RepoHealth(
            name="repo1",
            full_name="org/repo1",
            url="https://github.com/org/repo1",
            status=HealthStatus.HEALTHY,
            score=85.0,
            language=Language.PYTHON,
            metrics=RepoMetrics(),
        )

    @pytest.mark.asyncio
    async def test_scan_all_success(
        self, mock_repos: list[dict], mock_health: RepoHealth
    ) -> None:
        """Test successful scan_all."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repositories = AsyncMock(return_value=mock_repos)
            mock_client.build_repo_health = AsyncMock(return_value=mock_health)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            summary = await monitor.scan_all()

            assert summary.total_repos == 2
            assert summary.organization == monitor.organization

    @pytest.mark.asyncio
    async def test_scan_all_with_max_repos(
        self, mock_repos: list[dict], mock_health: RepoHealth
    ) -> None:
        """Test scan_all respects max_repos limit."""
        monitor = EcosystemMonitor()
        monitor.config.monitoring.max_repos = 1

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repositories = AsyncMock(return_value=mock_repos)
            mock_client.build_repo_health = AsyncMock(return_value=mock_health)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            summary = await monitor.scan_all()

            assert summary.total_repos == 1

    @pytest.mark.asyncio
    async def test_scan_all_rate_limit(self, mock_repos: list[dict]) -> None:
        """Test scan_all handles rate limit."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repositories = AsyncMock(return_value=mock_repos)
            mock_client.build_repo_health = AsyncMock(
                side_effect=RateLimitExceeded(datetime.now())
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(MonitorError) as exc_info:
                await monitor.scan_all()
            assert "rate limit" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_scan_all_api_error_continues(
        self, mock_repos: list[dict]
    ) -> None:
        """Test scan_all continues after single repo API error."""
        monitor = EcosystemMonitor()
        good_health = RepoHealth(
            name="repo2",
            full_name="org/repo2",
            url="https://github.com/org/repo2",
            status=HealthStatus.HEALTHY,
            score=85.0,
            language=Language.RUST,
            metrics=RepoMetrics(),
        )

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repositories = AsyncMock(return_value=mock_repos)
            mock_client.build_repo_health = AsyncMock(
                side_effect=[GitHubAPIError("Error", 500), good_health]
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            summary = await monitor.scan_all()

            # Should have both repos - one with UNKNOWN status from error
            assert summary.total_repos == 2

    @pytest.mark.asyncio
    async def test_scan_all_external_rate_limit(self) -> None:
        """Test scan_all handles rate limit from get_repositories."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repositories = AsyncMock(
                side_effect=RateLimitExceeded(datetime.now())
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(MonitorError):
                await monitor.scan_all()

    @pytest.mark.asyncio
    async def test_scan_all_external_api_error(self) -> None:
        """Test scan_all handles API error from get_repositories."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repositories = AsyncMock(
                side_effect=GitHubAPIError("Error", 500)
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(MonitorError):
                await monitor.scan_all()

    @pytest.mark.asyncio
    async def test_scan_repo_success(self, mock_health: RepoHealth) -> None:
        """Test successful single repo scan."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repository = AsyncMock(
                return_value={"name": "repo1", "full_name": "org/repo1"}
            )
            mock_client.build_repo_health = AsyncMock(return_value=mock_health)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            health = await monitor.scan_repo("repo1")
            assert health.name == "repo1"

    @pytest.mark.asyncio
    async def test_scan_repo_error(self) -> None:
        """Test scan_repo error handling."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repository = AsyncMock(
                side_effect=GitHubAPIError("Not found", 404)
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(MonitorError):
                await monitor.scan_repo("nonexistent")

    @pytest.mark.asyncio
    async def test_scan_repos_success(self, mock_health: RepoHealth) -> None:
        """Test successful multiple repos scan."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repository = AsyncMock(
                return_value={"name": "repo1", "full_name": "org/repo1"}
            )
            mock_client.build_repo_health = AsyncMock(return_value=mock_health)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            summary = await monitor.scan_repos(["repo1", "repo2"])
            assert summary.total_repos == 2

    @pytest.mark.asyncio
    async def test_scan_repos_api_error_continues(self, mock_health: RepoHealth) -> None:
        """Test scan_repos continues after single repo error."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repository = AsyncMock(
                side_effect=[GitHubAPIError("Error", 500), {"name": "repo2", "full_name": "org/repo2"}]
            )
            mock_client.build_repo_health = AsyncMock(return_value=mock_health)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            summary = await monitor.scan_repos(["repo1", "repo2"])
            # Should have both repos - one with UNKNOWN status
            assert summary.total_repos == 2

    @pytest.mark.asyncio
    async def test_scan_repos_rate_limit(self) -> None:
        """Test scan_repos handles rate limit from context manager entry."""
        monitor = EcosystemMonitor()

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            # RateLimitExceeded extends GitHubAPIError, so when raised from
            # get_repository it gets caught by the inner except GitHubAPIError
            # block. To test the outer rate limit handler, we need to raise it
            # from outside the per-repo try block, e.g., from __aenter__.
            mock_client.__aenter__ = AsyncMock(side_effect=RateLimitExceeded(datetime.now()))
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(MonitorError):
                await monitor.scan_repos(["repo1"])

    @pytest.mark.asyncio
    async def test_scan_all_progress_callback(
        self, mock_repos: list[dict], mock_health: RepoHealth
    ) -> None:
        """Test scan_all calls progress callback."""
        monitor = EcosystemMonitor()
        progress_calls = []

        def progress_callback(repo: str, current: int, total: int) -> None:
            progress_calls.append((repo, current, total))

        monitor.set_progress_callback(progress_callback)

        with patch("pulse.monitor.GitHubClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get_repositories = AsyncMock(return_value=mock_repos)
            mock_client.build_repo_health = AsyncMock(return_value=mock_health)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            await monitor.scan_all()

            assert len(progress_calls) == 2


class TestEcosystemMonitorRepoFilters:
    """Tests for repo filter methods with data."""

    @pytest.fixture
    def monitor_with_summary(self) -> EcosystemMonitor:
        """Create monitor with sample summary data."""
        monitor = EcosystemMonitor()

        summary = EcosystemSummary(organization="test-org")

        # Healthy repo
        healthy = RepoHealth(
            name="healthy-repo",
            full_name="org/healthy-repo",
            url="https://github.com/org/healthy-repo",
            status=HealthStatus.HEALTHY,
            score=90.0,
            language=Language.PYTHON,
            latest_build=BuildStatus.PASSING,
            last_commit=datetime.now() - timedelta(days=5),
            metrics=RepoMetrics(),
        )
        summary.add_repo(healthy)

        # Warning repo
        warning = RepoHealth(
            name="warning-repo",
            full_name="org/warning-repo",
            url="https://github.com/org/warning-repo",
            status=HealthStatus.WARNING,
            score=60.0,
            language=Language.RUST,
            latest_build=BuildStatus.PASSING,
            last_commit=datetime.now() - timedelta(days=60),
            metrics=RepoMetrics(),
        )
        summary.add_repo(warning)

        # Critical repo with vulnerabilities
        critical = RepoHealth(
            name="critical-repo",
            full_name="org/critical-repo",
            url="https://github.com/org/critical-repo",
            status=HealthStatus.CRITICAL,
            score=25.0,
            language=Language.JAVASCRIPT,
            latest_build=BuildStatus.FAILING,
            last_commit=datetime.now() - timedelta(days=120),
            metrics=RepoMetrics(),
            vulnerability_report=VulnerabilityReport(
                repo_name="critical-repo",
                total_alerts=5,
                critical_count=2,
            ),
        )
        summary.add_repo(critical)

        # Stale repo
        stale = RepoHealth(
            name="stale-repo",
            full_name="org/stale-repo",
            url="https://github.com/org/stale-repo",
            status=HealthStatus.WARNING,
            score=50.0,
            language=Language.SHELL,
            latest_build=BuildStatus.UNKNOWN,
            last_commit=datetime.now() - timedelta(days=180),
            metrics=RepoMetrics(),
        )
        summary.add_repo(stale)

        monitor._summary = summary
        return monitor

    def test_get_critical_repos(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test get_critical_repos returns critical repos."""
        repos = monitor_with_summary.get_critical_repos()
        assert len(repos) == 1
        assert repos[0].name == "critical-repo"

    def test_get_repos_needing_attention(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test get_repos_needing_attention returns warning and critical repos."""
        repos = monitor_with_summary.get_repos_needing_attention()
        assert len(repos) == 3  # warning + critical + stale
        names = [r.name for r in repos]
        assert "warning-repo" in names
        assert "critical-repo" in names
        assert "stale-repo" in names

    def test_get_vulnerable_repos(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test get_vulnerable_repos returns repos with vulnerabilities."""
        repos = monitor_with_summary.get_vulnerable_repos()
        assert len(repos) == 1
        assert repos[0].name == "critical-repo"

    def test_get_failing_builds(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test get_failing_builds returns repos with failing builds."""
        repos = monitor_with_summary.get_failing_builds()
        assert len(repos) == 1
        assert repos[0].name == "critical-repo"

    def test_get_stale_repos_default(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test get_stale_repos with default 90 days."""
        repos = monitor_with_summary.get_stale_repos()
        assert len(repos) == 2  # critical-repo (120 days) and stale-repo (180 days)

    def test_get_stale_repos_custom_days(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test get_stale_repos with custom days."""
        repos = monitor_with_summary.get_stale_repos(days=150)
        assert len(repos) == 1  # Only stale-repo (180 days)
        assert repos[0].name == "stale-repo"


class TestEcosystemMonitorExport:
    """Tests for export functionality."""

    @pytest.fixture
    def monitor_with_summary(self) -> EcosystemMonitor:
        """Create monitor with sample summary data."""
        monitor = EcosystemMonitor()
        summary = EcosystemSummary(organization="test-org")

        repo = RepoHealth(
            name="test-repo",
            full_name="org/test-repo",
            url="https://github.com/org/test-repo",
            status=HealthStatus.HEALTHY,
            score=85.0,
            language=Language.PYTHON,
            latest_build=BuildStatus.PASSING,
            last_commit=datetime.now() - timedelta(days=5),
            metrics=RepoMetrics(stars=100, open_issues=5),
            vulnerability_report=VulnerabilityReport(
                repo_name="test-repo",
                total_alerts=2,
                critical_count=1,
                high_count=1,
            ),
        )
        summary.add_repo(repo)

        critical_repo = RepoHealth(
            name="critical-repo",
            full_name="org/critical-repo",
            url="https://github.com/org/critical-repo",
            status=HealthStatus.CRITICAL,
            score=25.0,
            language=Language.RUST,
            latest_build=BuildStatus.FAILING,
            metrics=RepoMetrics(),
            vulnerability_report=VulnerabilityReport(
                repo_name="critical-repo",
                total_alerts=5,
                critical_count=3,
                high_count=2,
            ),
        )
        summary.add_repo(critical_repo)

        monitor._summary = summary
        return monitor

    def test_export_json(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test JSON export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            monitor_with_summary.export_json(path)

            assert path.exists()
            data = json.loads(path.read_text())
            assert "summary" in data
            assert "repos" in data
            assert len(data["repos"]) == 2

    def test_export_json_creates_directory(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test JSON export creates parent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "dir" / "report.json"
            monitor_with_summary.export_json(path)

            assert path.exists()

    def test_export_json_no_summary(self) -> None:
        """Test JSON export without summary raises error."""
        monitor = EcosystemMonitor()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            with pytest.raises(MonitorError):
                monitor.export_json(path)

    def test_export_json_string_path(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test JSON export with string path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = f"{tmpdir}/report.json"
            monitor_with_summary.export_json(path)

            assert Path(path).exists()

    def test_export_markdown(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test Markdown export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            monitor_with_summary.export_markdown(path)

            assert path.exists()
            content = path.read_text()
            assert "# Ecosystem Health Report" in content
            assert "test-org" in content
            assert "test-repo" in content

    def test_export_markdown_creates_directory(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test Markdown export creates parent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "dir" / "report.md"
            monitor_with_summary.export_markdown(path)

            assert path.exists()

    def test_export_markdown_no_summary(self) -> None:
        """Test Markdown export without summary raises error."""
        monitor = EcosystemMonitor()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            with pytest.raises(MonitorError):
                monitor.export_markdown(path)

    def test_export_markdown_includes_critical(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test Markdown export includes critical issues section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            monitor_with_summary.export_markdown(path)

            content = path.read_text()
            assert "Critical Issues" in content
            assert "critical-repo" in content

    def test_export_markdown_includes_vulnerabilities(self, monitor_with_summary: EcosystemMonitor) -> None:
        """Test Markdown export includes vulnerabilities section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            monitor_with_summary.export_markdown(path)

            content = path.read_text()
            assert "Security Vulnerabilities" in content


class TestRunScan:
    """Tests for run_scan synchronous wrapper."""

    def test_run_scan_basic(self) -> None:
        """Test basic run_scan."""
        mock_summary = EcosystemSummary(organization="test-org")
        mock_summary.add_repo(
            RepoHealth(
                name="repo",
                full_name="org/repo",
                url="https://github.com/org/repo",
                status=HealthStatus.HEALTHY,
                score=85.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
        )

        with patch("pulse.monitor.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = MagicMock()
            mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            summary = run_scan()
            assert summary.total_repos == 1

    def test_run_scan_with_org(self) -> None:
        """Test run_scan with org parameter."""
        mock_summary = EcosystemSummary(organization="custom-org")

        with patch("pulse.monitor.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = MagicMock()
            mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            summary = run_scan(org="custom-org")
            assert summary.organization == "custom-org"

    def test_run_scan_with_config_path(self) -> None:
        """Test run_scan with config path."""
        mock_summary = EcosystemSummary(organization="test-org")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "pulse.yaml"
            config_path.write_text("github:\n  organization: test-org\n")

            with patch("pulse.monitor.EcosystemMonitor") as mock_monitor_cls:
                mock_monitor = MagicMock()
                mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
                mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
                mock_monitor.__aexit__ = AsyncMock(return_value=None)
                mock_monitor_cls.return_value = mock_monitor

                summary = run_scan(config_path=str(config_path))
                assert summary is not None
