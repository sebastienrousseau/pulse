"""Tests for trends module."""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    RepoHealth,
)
from pulse.trends import (
    HistoricalDataPoint,
    RepoHistoricalDataPoint,
    TrendAnalysis,
    TrendAnalyzer,
    TrendStore,
)


class TestHistoricalDataPoint:
    """Tests for HistoricalDataPoint."""

    def test_from_summary(self) -> None:
        """Test creating from ecosystem summary."""
        summary = EcosystemSummary(organization="test-org")
        summary.total_repos = 10
        summary.healthy_count = 7
        summary.warning_count = 2
        summary.critical_count = 1
        summary.average_score = 75.5
        summary.total_vulnerabilities = 3
        summary.total_stars = 100
        summary.total_open_issues = 25

        point = HistoricalDataPoint.from_summary(summary)

        assert point.organization == "test-org"
        assert point.total_repos == 10
        assert point.healthy_count == 7
        assert point.average_score == 75.5

    def test_serialization(self) -> None:
        """Test serialization round trip."""
        point = HistoricalDataPoint(
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            organization="myorg",
            total_repos=5,
            healthy_count=4,
            warning_count=1,
            critical_count=0,
            average_score=85.0,
            total_vulnerabilities=2,
            total_stars=50,
            total_open_issues=10,
        )

        data = point.to_dict()
        restored = HistoricalDataPoint.from_dict(data)

        assert restored.organization == point.organization
        assert restored.total_repos == point.total_repos
        assert restored.average_score == point.average_score


class TestRepoHistoricalDataPoint:
    """Tests for RepoHistoricalDataPoint."""

    def test_from_repo_health(self) -> None:
        """Test creating from repo health."""
        repo = RepoHealth(
            name="test-repo",
            full_name="org/test-repo",
            url="https://github.com/org/test-repo",
            status=HealthStatus.HEALTHY,
            score=85.0,
            latest_build=BuildStatus.PASSING,
        )

        point = RepoHistoricalDataPoint.from_repo_health(repo)

        assert point.repo_name == "test-repo"
        assert point.score == 85.0
        assert point.status == HealthStatus.HEALTHY
        assert point.build_passing is True

    def test_serialization(self) -> None:
        """Test serialization round trip."""
        point = RepoHistoricalDataPoint(
            timestamp=datetime(2024, 1, 15),
            repo_name="test-repo",
            score=75.0,
            status=HealthStatus.WARNING,
            vulnerabilities=2,
            build_passing=False,
            days_since_commit=5,
        )

        data = point.to_dict()
        restored = RepoHistoricalDataPoint.from_dict(data)

        assert restored.repo_name == point.repo_name
        assert restored.score == point.score
        assert restored.status == point.status


class TestTrendAnalysis:
    """Tests for TrendAnalysis."""

    def test_improving_score(self) -> None:
        """Test improving trend detection."""
        analysis = TrendAnalysis(
            metric_name="average_score",
            current_value=80.0,
            previous_value=70.0,
            change=10.0,
            change_percent=14.3,
            direction="up",
            period_days=30,
            data_points=10,
        )

        assert analysis.is_improving is True

    def test_improving_vulnerabilities(self) -> None:
        """Test vulnerability trend (down is improving)."""
        analysis = TrendAnalysis(
            metric_name="total_vulnerabilities",
            current_value=2.0,
            previous_value=5.0,
            change=-3.0,
            change_percent=-60.0,
            direction="down",
            period_days=30,
            data_points=10,
        )

        assert analysis.is_improving is True

    def test_stable_trend(self) -> None:
        """Test stable trend."""
        analysis = TrendAnalysis(
            metric_name="average_score",
            current_value=75.0,
            previous_value=75.0,
            change=0.0,
            change_percent=0.0,
            direction="stable",
            period_days=30,
            data_points=5,
        )

        assert analysis.direction == "stable"

    def test_to_dict(self) -> None:
        """Test serialization."""
        analysis = TrendAnalysis(
            metric_name="test",
            current_value=100.0,
            previous_value=90.0,
            change=10.0,
            change_percent=11.11,
            direction="up",
            period_days=7,
            data_points=7,
        )

        data = analysis.to_dict()

        assert data["metric_name"] == "test"
        assert data["change_percent"] == 11.11
        assert "is_improving" in data


class TestTrendStore:
    """Tests for TrendStore."""

    @pytest.fixture
    def store_dir(self) -> Path:
        """Create temporary store directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def store(self, store_dir: Path) -> TrendStore:
        """Create trend store."""
        return TrendStore(store_dir)

    def test_save_and_load_summary(self, store: TrendStore) -> None:
        """Test saving and loading summary."""
        summary = EcosystemSummary(organization="test-org")
        summary.total_repos = 5
        summary.healthy_count = 4
        summary.average_score = 80.0

        store.save_summary(summary)
        history = store.load_summary_history("test-org")

        assert len(history) == 1
        assert history[0].total_repos == 5
        assert history[0].average_score == 80.0

    def test_save_multiple_summaries(self, store: TrendStore) -> None:
        """Test saving multiple summaries."""
        for i in range(3):
            summary = EcosystemSummary(organization="test-org")
            summary.total_repos = i + 1
            store.save_summary(summary)

        history = store.load_summary_history("test-org")
        assert len(history) == 3

    def test_load_with_time_range(self, store: TrendStore) -> None:
        """Test loading with time filters."""
        now = datetime.now()

        # Create summary with custom timestamp
        summary = EcosystemSummary(organization="test-org")
        summary.generated_at = now - timedelta(days=5)
        store.save_summary(summary)

        # Load with filter that excludes it
        since = now - timedelta(days=2)
        history = store.load_summary_history("test-org", since=since)
        assert len(history) == 0

        # Load with filter that includes it
        since = now - timedelta(days=10)
        history = store.load_summary_history("test-org", since=since)
        assert len(history) == 1

    def test_save_and_load_repo_data(self, store: TrendStore) -> None:
        """Test saving and loading repo data."""
        repos = [
            RepoHealth(
                name="repo1",
                full_name="org/repo1",
                url="https://github.com/org/repo1",
                score=80.0,
                status=HealthStatus.HEALTHY,
            ),
            RepoHealth(
                name="repo2",
                full_name="org/repo2",
                url="https://github.com/org/repo2",
                score=60.0,
                status=HealthStatus.WARNING,
            ),
        ]

        store.save_repo_data("test-org", repos)
        history = store.load_repo_history("test-org")

        assert len(history) == 2

    def test_load_repo_filtered(self, store: TrendStore) -> None:
        """Test loading specific repo history."""
        repos = [
            RepoHealth(
                name="repo1",
                full_name="org/repo1",
                url="url1",
                score=80.0,
            ),
            RepoHealth(
                name="repo2",
                full_name="org/repo2",
                url="url2",
                score=60.0,
            ),
        ]

        store.save_repo_data("test-org", repos)
        history = store.load_repo_history("test-org", repo_name="repo1")

        assert len(history) == 1
        assert history[0].repo_name == "repo1"

    def test_get_organizations(self, store: TrendStore) -> None:
        """Test getting tracked organizations."""
        summary1 = EcosystemSummary(organization="org1")
        summary2 = EcosystemSummary(organization="org2")

        store.save_summary(summary1)
        store.save_summary(summary2)

        orgs = store.get_organizations()
        assert "org1" in orgs
        assert "org2" in orgs

    def test_cleanup(self, store: TrendStore) -> None:
        """Test cleanup of old data."""
        # Save old entry
        summary = EcosystemSummary(organization="test-org")
        summary.generated_at = datetime.now() - timedelta(days=400)
        store.save_summary(summary)

        # Save recent entry
        summary2 = EcosystemSummary(organization="test-org")
        store.save_summary(summary2)

        # Cleanup keeping 365 days
        removed = store.cleanup("test-org", keep_days=365)
        assert removed == 1

        history = store.load_summary_history("test-org")
        assert len(history) == 1


class TestTrendAnalyzer:
    """Tests for TrendAnalyzer."""

    @pytest.fixture
    def store_dir(self) -> Path:
        """Create temporary store directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def analyzer(self, store_dir: Path) -> TrendAnalyzer:
        """Create analyzer with populated store."""
        store = TrendStore(store_dir)

        # Add historical data
        for i in range(10):
            summary = EcosystemSummary(organization="test-org")
            summary.generated_at = datetime.now() - timedelta(days=9 - i)
            summary.total_repos = 10
            summary.healthy_count = 5 + i // 2
            summary.warning_count = 3
            summary.critical_count = 2 - i // 5
            summary.average_score = 70.0 + i
            summary.total_vulnerabilities = 10 - i
            summary.total_stars = 100 + i * 5
            summary.total_open_issues = 20 - i // 2
            store.save_summary(summary)

        return TrendAnalyzer(store)

    def test_analyze_summary_trends(self, analyzer: TrendAnalyzer) -> None:
        """Test summary trend analysis."""
        trends = analyzer.analyze_summary_trends("test-org", days=30)

        assert len(trends) > 0

        # Find score trend
        score_trend = next(
            (t for t in trends if t.metric_name == "Average Score"),
            None
        )
        assert score_trend is not None
        assert score_trend.direction == "up"

    def test_analyze_repo_trends(self, store_dir: Path) -> None:
        """Test repo-level trend analysis."""
        store = TrendStore(store_dir)

        # Add repo data
        for i in range(5):
            repo = RepoHealth(
                name="test-repo",
                full_name="org/test-repo",
                url="url",
                score=70.0 + i * 5,
                status=HealthStatus.WARNING,
            )
            store.save_repo_data(
                "test-org",
                [repo],
                timestamp=datetime.now() - timedelta(days=4 - i),
            )

        analyzer = TrendAnalyzer(store)
        trends = analyzer.analyze_repo_trends("test-org", "test-repo", days=30)

        assert len(trends) > 0
        score_trend = next(
            (t for t in trends if t.metric_name == "Score"),
            None
        )
        assert score_trend is not None
        assert score_trend.direction == "up"

    def test_insufficient_data(self, store_dir: Path) -> None:
        """Test analysis with insufficient data."""
        store = TrendStore(store_dir)
        analyzer = TrendAnalyzer(store)

        trends = analyzer.analyze_summary_trends("nonexistent", days=30)
        assert trends == []

    def test_compare_periods(self, analyzer: TrendAnalyzer) -> None:
        """Test period comparison."""
        comparison = analyzer.compare_periods("test-org", period1_days=3, period2_days=3)

        assert "average_score" in comparison
        assert "period1" in comparison["average_score"]
        assert "period2" in comparison["average_score"]
        assert "change" in comparison["average_score"]

    def test_generate_report(self, analyzer: TrendAnalyzer) -> None:
        """Test full report generation."""
        report = analyzer.generate_report("test-org", days=30)

        assert report["organization"] == "test-org"
        assert "trends" in report
        assert "period_comparison" in report
        assert "summary" in report
        assert "generated_at" in report

    def test_get_score_percentiles(self, store_dir: Path) -> None:
        """Test score percentile calculation."""
        store = TrendStore(store_dir)

        # Add varied scores
        scores = [50, 60, 70, 80, 90, 100, 75, 85, 65, 55]
        for i, score in enumerate(scores):
            repo = RepoHealth(
                name="test-repo",
                full_name="org/test-repo",
                url="url",
                score=float(score),
            )
            store.save_repo_data(
                "test-org",
                [repo],
                timestamp=datetime.now() - timedelta(days=len(scores) - i),
            )

        analyzer = TrendAnalyzer(store)
        percentiles = analyzer.get_score_percentiles("test-org", "test-repo", days=90)

        assert "min" in percentiles
        assert "max" in percentiles
        assert "median" in percentiles
        assert "mean" in percentiles
        assert percentiles["min"] == 50
        assert percentiles["max"] == 100

    def test_get_status_history(self, store_dir: Path) -> None:
        """Test status change history."""
        store = TrendStore(store_dir)

        statuses = [
            HealthStatus.HEALTHY,
            HealthStatus.HEALTHY,
            HealthStatus.WARNING,
            HealthStatus.WARNING,
            HealthStatus.CRITICAL,
            HealthStatus.WARNING,
            HealthStatus.HEALTHY,
        ]

        for i, status in enumerate(statuses):
            repo = RepoHealth(
                name="test-repo",
                full_name="org/test-repo",
                url="url",
                status=status,
                score=50.0,
            )
            store.save_repo_data(
                "test-org",
                [repo],
                timestamp=datetime.now() - timedelta(days=len(statuses) - i),
            )

        analyzer = TrendAnalyzer(store)
        history = analyzer.get_status_history("test-org", "test-repo", days=30)

        # Should capture status changes
        assert len(history) >= 4  # At least 4 unique status transitions
