"""Tests for Pulse data models."""

from datetime import datetime, timedelta

import pytest

from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    Language,
    RepoHealth,
    RepoMetrics,
    SecurityAlert,
    Severity,
    VulnerabilityReport,
)


class TestRepoHealth:
    """Tests for RepoHealth model."""

    def test_create_basic_repo(self) -> None:
        """Test creating a basic RepoHealth instance."""
        health = RepoHealth(
            name="test-repo",
            full_name="org/test-repo",
            url="https://github.com/org/test-repo",
        )

        assert health.name == "test-repo"
        assert health.status == HealthStatus.UNKNOWN
        assert health.score == 0.0

    def test_is_healthy(self) -> None:
        """Test is_healthy property."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
            status=HealthStatus.HEALTHY,
        )
        assert health.is_healthy is True

        health.status = HealthStatus.WARNING
        assert health.is_healthy is False

    def test_needs_attention(self) -> None:
        """Test needs_attention property."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
        )

        health.status = HealthStatus.HEALTHY
        assert health.needs_attention is False

        health.status = HealthStatus.WARNING
        assert health.needs_attention is True

        health.status = HealthStatus.CRITICAL
        assert health.needs_attention is True

    def test_days_since_commit(self) -> None:
        """Test days_since_commit calculation."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
            last_commit=datetime.now() - timedelta(days=5),
        )

        assert health.days_since_commit == 5

    def test_days_since_commit_none(self) -> None:
        """Test days_since_commit with no commit date."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
        )

        assert health.days_since_commit is None

    def test_calculate_score_base(self) -> None:
        """Test base score calculation."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
        )

        score = health.calculate_score()
        assert score == 50.0  # Base score

    def test_calculate_score_with_passing_build(self) -> None:
        """Test score with passing build."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
            latest_build=BuildStatus.PASSING,
        )

        score = health.calculate_score()
        assert score == 65.0  # Base + 15

    def test_calculate_score_with_failing_build(self) -> None:
        """Test score with failing build."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
            latest_build=BuildStatus.FAILING,
        )

        score = health.calculate_score()
        assert score == 35.0  # Base - 15

    def test_calculate_score_with_quality_indicators(self) -> None:
        """Test score with quality indicators."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
            has_readme=True,
            has_license=True,
            has_ci=True,
            has_tests=True,
            has_docs=True,
        )

        score = health.calculate_score()
        # Base 50 + readme 5 + docs 5 + license 5 + ci 5 + tests 5 = 75
        assert score == 75.0

    def test_calculate_score_with_recent_activity(self) -> None:
        """Test score with recent activity."""
        health = RepoHealth(
            name="test",
            full_name="org/test",
            url="https://github.com/org/test",
            last_commit=datetime.now() - timedelta(days=10),
        )

        score = health.calculate_score()
        assert score == 60.0  # Base + 10 for recent activity


class TestVulnerabilityReport:
    """Tests for VulnerabilityReport model."""

    def test_has_critical(self) -> None:
        """Test has_critical property."""
        report = VulnerabilityReport(
            repo_name="test",
            critical_count=1,
        )
        assert report.has_critical is True

        report.critical_count = 0
        assert report.has_critical is False

    def test_severity_score(self) -> None:
        """Test severity score calculation."""
        report = VulnerabilityReport(
            repo_name="test",
            critical_count=1,  # 40 points
            high_count=2,  # 40 points
            medium_count=3,  # 15 points
            low_count=4,  # 4 points
        )

        # 40 + 40 + 15 + 4 = 99
        assert report.severity_score == 99.0

    def test_severity_score_max(self) -> None:
        """Test severity score capped at 100."""
        report = VulnerabilityReport(
            repo_name="test",
            critical_count=10,  # Would be 400
        )

        assert report.severity_score == 100.0


class TestEcosystemSummary:
    """Tests for EcosystemSummary model."""

    def test_add_repo(self) -> None:
        """Test adding repository to summary."""
        summary = EcosystemSummary(organization="test-org")

        health = RepoHealth(
            name="test-repo",
            full_name="test-org/test-repo",
            url="https://github.com/test-org/test-repo",
            status=HealthStatus.HEALTHY,
            score=80.0,
            language=Language.RUST,
        )
        health.metrics = RepoMetrics(stars=100, forks=10, open_issues=5)

        summary.add_repo(health)

        assert summary.total_repos == 1
        assert summary.healthy_count == 1
        assert summary.total_stars == 100
        assert summary.total_forks == 10
        assert summary.total_open_issues == 5
        assert summary.language_breakdown["rust"] == 1

    def test_health_percentage(self) -> None:
        """Test health percentage calculation."""
        summary = EcosystemSummary(organization="test-org")

        for status in [HealthStatus.HEALTHY, HealthStatus.HEALTHY, HealthStatus.WARNING]:
            health = RepoHealth(
                name=f"repo-{status.value}",
                full_name=f"test-org/repo-{status.value}",
                url=f"https://github.com/test-org/repo-{status.value}",
                status=status,
            )
            summary.add_repo(health)

        # 2 out of 3 healthy = 66.67%
        assert abs(summary.health_percentage - 66.67) < 0.1

    def test_health_percentage_empty(self) -> None:
        """Test health percentage with no repos."""
        summary = EcosystemSummary(organization="test-org")
        assert summary.health_percentage == 0.0

    def test_to_dict(self) -> None:
        """Test summary serialization."""
        summary = EcosystemSummary(organization="test-org")
        data = summary.to_dict()

        assert data["organization"] == "test-org"
        assert data["total_repos"] == 0
        assert "generated_at" in data


class TestSecurityAlert:
    """Tests for SecurityAlert model."""

    def test_create_alert(self) -> None:
        """Test creating a security alert."""
        alert = SecurityAlert(
            id="1",
            package="vulnerable-pkg",
            severity=Severity.HIGH,
            title="High severity vulnerability",
            description="A serious security issue",
            cve_id="CVE-2024-1234",
        )

        assert alert.package == "vulnerable-pkg"
        assert alert.severity == Severity.HIGH
        assert alert.cve_id == "CVE-2024-1234"
