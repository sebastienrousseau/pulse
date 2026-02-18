"""Tests for Pulse dashboard generation."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pulse.config import PulseConfig
from pulse.dashboard import DashboardGenerator
from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    Language,
    RepoHealth,
    RepoMetrics,
    VulnerabilityReport,
)


class TestDashboardGenerator:
    """Tests for DashboardGenerator."""

    @pytest.fixture
    def config(self) -> PulseConfig:
        """Create test config."""
        return PulseConfig()

    @pytest.fixture
    def generator(self, config: PulseConfig) -> DashboardGenerator:
        """Create dashboard generator."""
        return DashboardGenerator(config)

    @pytest.fixture
    def summary(self) -> EcosystemSummary:
        """Create test summary."""
        summary = EcosystemSummary(organization="test-org")

        # Add healthy repo
        healthy_repo = RepoHealth(
            name="healthy-repo",
            full_name="test-org/healthy-repo",
            url="https://github.com/test-org/healthy-repo",
            status=HealthStatus.HEALTHY,
            score=90.0,
            language=Language.RUST,
            latest_build=BuildStatus.PASSING,
            metrics=RepoMetrics(stars=100, forks=20, open_issues=5),
            vulnerability_report=VulnerabilityReport(
                repo_name="healthy-repo",
                total_alerts=0,
            ),
        )
        summary.add_repo(healthy_repo)

        # Add warning repo
        warning_repo = RepoHealth(
            name="warning-repo",
            full_name="test-org/warning-repo",
            url="https://github.com/test-org/warning-repo",
            status=HealthStatus.WARNING,
            score=60.0,
            language=Language.PYTHON,
            latest_build=BuildStatus.FAILING,
            metrics=RepoMetrics(stars=50, forks=10, open_issues=15),
            vulnerability_report=VulnerabilityReport(
                repo_name="warning-repo",
                total_alerts=3,
                high_count=2,
                medium_count=1,
            ),
        )
        summary.add_repo(warning_repo)

        # Add critical repo
        critical_repo = RepoHealth(
            name="critical-repo",
            full_name="test-org/critical-repo",
            url="https://github.com/test-org/critical-repo",
            status=HealthStatus.CRITICAL,
            score=25.0,
            language=Language.JAVASCRIPT,
            latest_build=BuildStatus.UNKNOWN,
            metrics=RepoMetrics(stars=10, forks=2, open_issues=30),
            vulnerability_report=VulnerabilityReport(
                repo_name="critical-repo",
                total_alerts=10,
                critical_count=5,
            ),
        )
        summary.add_repo(critical_repo)

        return summary

    def test_init(self, config: PulseConfig) -> None:
        """Test generator initialization."""
        generator = DashboardGenerator(config)
        assert generator.config == config
        assert generator._env is None

    def test_get_env_default(self, generator: DashboardGenerator) -> None:
        """Test getting Jinja2 environment."""
        env = generator._get_env()
        assert env is not None
        # Should be cached
        assert generator._get_env() is env

    def test_get_env_fallback(self, generator: DashboardGenerator) -> None:
        """Test environment fallback when templates not found."""
        with patch("pulse.dashboard.PackageLoader", side_effect=ValueError("No templates")):
            env = generator._get_env()
            assert env is not None

    def test_generate_inline_dashboard_dark_theme(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test inline dashboard generation with dark theme."""
        generator.config.dashboard.theme = "dark"
        html = generator._generate_inline_dashboard(summary)

        assert "<!DOCTYPE html>" in html
        assert "Pulse Dashboard" in html
        assert "test-org" in html
        assert "#1a1a2e" in html  # Dark background color
        assert "healthy-repo" in html
        assert "warning-repo" in html
        assert "critical-repo" in html

    def test_generate_inline_dashboard_light_theme(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test inline dashboard generation with light theme."""
        generator.config.dashboard.theme = "light"
        html = generator._generate_inline_dashboard(summary)

        assert "<!DOCTYPE html>" in html
        assert "#ffffff" in html  # Light background color

    def test_generate_inline_dashboard_content(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test dashboard content includes all metrics."""
        html = generator._generate_inline_dashboard(summary)

        # Check summary cards
        assert "Total Repositories" in html
        assert "Healthy" in html
        assert "Warning" in html
        assert "Critical" in html
        assert "Avg Score" in html
        assert "Vulnerabilities" in html
        assert "Total Stars" in html
        assert "Open Issues" in html

        # Check repo table headers
        assert "Repository" in html
        assert "Status" in html
        assert "Score" in html
        assert "Language" in html
        assert "Build" in html
        assert "Vulns" in html
        assert "Stars" in html
        assert "Issues" in html

    def test_generate_inline_dashboard_repo_rows(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test dashboard repo rows are sorted by score."""
        html = generator._generate_inline_dashboard(summary)

        # Check repos are present (sorted by score descending)
        healthy_pos = html.find("healthy-repo")
        warning_pos = html.find("warning-repo")
        critical_pos = html.find("critical-repo")

        assert healthy_pos < warning_pos < critical_pos

    def test_generate_inline_dashboard_refresh_interval(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test dashboard has correct refresh interval."""
        generator.config.dashboard.refresh_interval_seconds = 300
        html = generator._generate_inline_dashboard(summary)

        assert 'content="300"' in html

    def test_generate_inline_dashboard_health_percentage(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test dashboard shows health percentage."""
        html = generator._generate_inline_dashboard(summary)

        assert "Health Distribution" in html
        assert "progress-bar" in html
        assert "% of repositories are healthy" in html

    def test_generate_creates_directory(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test generate creates output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "nested" / "dashboard"
            path = generator.generate(summary, output_dir)

            assert output_dir.exists()
            assert path.exists()
            assert path.name == "index.html"

    def test_generate_default_output_dir(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test generate uses config default output dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator.config.dashboard.output_dir = Path(tmpdir)
            path = generator.generate(summary)

            assert path.exists()
            assert path.parent == Path(tmpdir)

    def test_generate_string_output_dir(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test generate accepts string output dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generator.generate(summary, tmpdir)

            assert path.exists()
            assert str(path.parent) == tmpdir

    def test_generate_writes_html(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test generate writes valid HTML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generator.generate(summary, tmpdir)

            content = path.read_text()
            assert "<!DOCTYPE html>" in content
            assert "</html>" in content

    def test_generate_returns_path(
        self, generator: DashboardGenerator, summary: EcosystemSummary
    ) -> None:
        """Test generate returns correct path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generator.generate(summary, tmpdir)

            assert isinstance(path, Path)
            assert path.name == "index.html"


class TestGenerateBadge:
    """Tests for badge generation."""

    @pytest.fixture
    def generator(self) -> DashboardGenerator:
        """Create dashboard generator."""
        return DashboardGenerator(PulseConfig())

    def test_generate_badge_healthy(self, generator: DashboardGenerator) -> None:
        """Test badge generation for healthy ecosystem."""
        summary = EcosystemSummary(organization="test-org")
        for i in range(10):
            repo = RepoHealth(
                name=f"repo-{i}",
                full_name=f"test-org/repo-{i}",
                url=f"https://github.com/test-org/repo-{i}",
                status=HealthStatus.HEALTHY,
                score=90.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)

        with tempfile.TemporaryDirectory() as tmpdir:
            badge_path = Path(tmpdir) / "badge.svg"
            path = generator.generate_badge(summary, badge_path)

            assert path.exists()
            content = path.read_text()
            assert "<svg" in content
            assert "health" in content
            assert "#4caf50" in content  # Green color
            assert "healthy" in content

    def test_generate_badge_warning(self, generator: DashboardGenerator) -> None:
        """Test badge generation for warning ecosystem."""
        summary = EcosystemSummary(organization="test-org")
        for i in range(10):
            status = HealthStatus.HEALTHY if i < 6 else HealthStatus.WARNING
            repo = RepoHealth(
                name=f"repo-{i}",
                full_name=f"test-org/repo-{i}",
                url=f"https://github.com/test-org/repo-{i}",
                status=status,
                score=70.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)

        with tempfile.TemporaryDirectory() as tmpdir:
            badge_path = Path(tmpdir) / "badge.svg"
            path = generator.generate_badge(summary, badge_path)

            content = path.read_text()
            assert "#ff9800" in content  # Orange color
            assert "warning" in content

    def test_generate_badge_critical(self, generator: DashboardGenerator) -> None:
        """Test badge generation for critical ecosystem."""
        summary = EcosystemSummary(organization="test-org")
        for i in range(10):
            status = HealthStatus.HEALTHY if i < 4 else HealthStatus.CRITICAL
            repo = RepoHealth(
                name=f"repo-{i}",
                full_name=f"test-org/repo-{i}",
                url=f"https://github.com/test-org/repo-{i}",
                status=status,
                score=30.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)

        with tempfile.TemporaryDirectory() as tmpdir:
            badge_path = Path(tmpdir) / "badge.svg"
            path = generator.generate_badge(summary, badge_path)

            content = path.read_text()
            assert "#f44336" in content  # Red color
            assert "critical" in content

    def test_generate_badge_creates_directory(self, generator: DashboardGenerator) -> None:
        """Test badge generation creates parent directory."""
        summary = EcosystemSummary(organization="test-org")
        summary.add_repo(
            RepoHealth(
                name="repo",
                full_name="test-org/repo",
                url="https://github.com/test-org/repo",
                status=HealthStatus.HEALTHY,
                score=90.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            badge_path = Path(tmpdir) / "nested" / "badges" / "health.svg"
            path = generator.generate_badge(summary, badge_path)

            assert badge_path.parent.exists()
            assert path.exists()

    def test_generate_badge_string_path(self, generator: DashboardGenerator) -> None:
        """Test badge generation accepts string path."""
        summary = EcosystemSummary(organization="test-org")
        summary.add_repo(
            RepoHealth(
                name="repo",
                full_name="test-org/repo",
                url="https://github.com/test-org/repo",
                status=HealthStatus.HEALTHY,
                score=90.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            badge_path = f"{tmpdir}/badge.svg"
            path = generator.generate_badge(summary, badge_path)

            assert path.exists()
            assert isinstance(path, Path)

    def test_generate_badge_percentage_display(self, generator: DashboardGenerator) -> None:
        """Test badge displays health percentage."""
        summary = EcosystemSummary(organization="test-org")
        # 8 healthy out of 10 = 80%
        for i in range(10):
            status = HealthStatus.HEALTHY if i < 8 else HealthStatus.CRITICAL
            repo = RepoHealth(
                name=f"repo-{i}",
                full_name=f"test-org/repo-{i}",
                url=f"https://github.com/test-org/repo-{i}",
                status=status,
                score=80.0 if status == HealthStatus.HEALTHY else 20.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)

        with tempfile.TemporaryDirectory() as tmpdir:
            badge_path = Path(tmpdir) / "badge.svg"
            path = generator.generate_badge(summary, badge_path)

            content = path.read_text()
            assert "80%" in content


class TestDashboardWithDifferentStatuses:
    """Tests for dashboard with various repo status combinations."""

    @pytest.fixture
    def generator(self) -> DashboardGenerator:
        """Create dashboard generator."""
        return DashboardGenerator(PulseConfig())

    def test_dashboard_with_repo_no_vulnerabilities(self, generator: DashboardGenerator) -> None:
        """Test dashboard with repo having no vulnerability report."""
        summary = EcosystemSummary(organization="test-org")
        repo = RepoHealth(
            name="repo",
            full_name="test-org/repo",
            url="https://github.com/test-org/repo",
            status=HealthStatus.HEALTHY,
            score=90.0,
            language=Language.RUST,
            latest_build=BuildStatus.PASSING,
            metrics=RepoMetrics(stars=50),
            vulnerability_report=None,
        )
        summary.add_repo(repo)

        html = generator._generate_inline_dashboard(summary)
        assert "repo" in html
        # Should display 0 vulnerabilities when report is None

    def test_dashboard_with_unknown_status(self, generator: DashboardGenerator) -> None:
        """Test dashboard with unknown status repo."""
        summary = EcosystemSummary(organization="test-org")
        repo = RepoHealth(
            name="unknown-repo",
            full_name="test-org/unknown-repo",
            url="https://github.com/test-org/unknown-repo",
            status=HealthStatus.UNKNOWN,
            score=0.0,
            language=Language.OTHER,
            latest_build=BuildStatus.UNKNOWN,
            metrics=RepoMetrics(),
        )
        summary.add_repo(repo)

        html = generator._generate_inline_dashboard(summary)
        assert "unknown-repo" in html

    def test_dashboard_empty_summary(self, generator: DashboardGenerator) -> None:
        """Test dashboard with empty summary."""
        summary = EcosystemSummary(organization="empty-org")

        html = generator._generate_inline_dashboard(summary)
        assert "empty-org" in html
        assert "Total Repositories" in html

    def test_dashboard_all_languages(self, generator: DashboardGenerator) -> None:
        """Test dashboard with all language types."""
        summary = EcosystemSummary(organization="test-org")
        languages = [
            Language.RUST,
            Language.PYTHON,
            Language.JAVASCRIPT,
            Language.TYPESCRIPT,
            Language.HTML,
            Language.SHELL,
            Language.OTHER,
        ]

        for i, lang in enumerate(languages):
            repo = RepoHealth(
                name=f"repo-{lang.value}",
                full_name=f"test-org/repo-{lang.value}",
                url=f"https://github.com/test-org/repo-{lang.value}",
                status=HealthStatus.HEALTHY,
                score=85.0,
                language=lang,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)

        html = generator._generate_inline_dashboard(summary)
        for lang in languages:
            assert lang.value in html

    def test_dashboard_all_build_statuses(self, generator: DashboardGenerator) -> None:
        """Test dashboard with all build statuses."""
        summary = EcosystemSummary(organization="test-org")
        build_statuses = [
            BuildStatus.PASSING,
            BuildStatus.FAILING,
            BuildStatus.PENDING,
            BuildStatus.UNKNOWN,
        ]

        for status in build_statuses:
            repo = RepoHealth(
                name=f"repo-{status.value}",
                full_name=f"test-org/repo-{status.value}",
                url=f"https://github.com/test-org/repo-{status.value}",
                status=HealthStatus.HEALTHY,
                score=85.0,
                language=Language.PYTHON,
                latest_build=status,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)

        html = generator._generate_inline_dashboard(summary)
        for status in build_statuses:
            assert status.value in html
