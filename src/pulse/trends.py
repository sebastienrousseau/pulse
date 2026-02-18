"""Historical trend analysis for Pulse.

Provides storage and analysis of historical ecosystem health data
to identify trends and patterns over time.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pulse.models import EcosystemSummary, HealthStatus, RepoHealth


class TrendError(Exception):
    """Trend analysis error."""

    pass


@dataclass
class HistoricalDataPoint:
    """Single historical data point."""

    timestamp: datetime
    organization: str
    total_repos: int
    healthy_count: int
    warning_count: int
    critical_count: int
    average_score: float
    total_vulnerabilities: int
    total_stars: int
    total_open_issues: int

    @classmethod
    def from_summary(cls, summary: EcosystemSummary) -> HistoricalDataPoint:
        """Create from ecosystem summary.

        Args:
            summary: Ecosystem summary.

        Returns:
            Historical data point.
        """
        return cls(
            timestamp=summary.generated_at,
            organization=summary.organization,
            total_repos=summary.total_repos,
            healthy_count=summary.healthy_count,
            warning_count=summary.warning_count,
            critical_count=summary.critical_count,
            average_score=summary.average_score,
            total_vulnerabilities=summary.total_vulnerabilities,
            total_stars=summary.total_stars,
            total_open_issues=summary.total_open_issues,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "organization": self.organization,
            "total_repos": self.total_repos,
            "healthy_count": self.healthy_count,
            "warning_count": self.warning_count,
            "critical_count": self.critical_count,
            "average_score": self.average_score,
            "total_vulnerabilities": self.total_vulnerabilities,
            "total_stars": self.total_stars,
            "total_open_issues": self.total_open_issues,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HistoricalDataPoint:
        """Deserialize from dictionary."""
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            organization=data["organization"],
            total_repos=data["total_repos"],
            healthy_count=data["healthy_count"],
            warning_count=data["warning_count"],
            critical_count=data["critical_count"],
            average_score=data["average_score"],
            total_vulnerabilities=data["total_vulnerabilities"],
            total_stars=data["total_stars"],
            total_open_issues=data["total_open_issues"],
        )


@dataclass
class RepoHistoricalDataPoint:
    """Historical data point for a single repository."""

    timestamp: datetime
    repo_name: str
    score: float
    status: HealthStatus
    vulnerabilities: int
    build_passing: bool
    days_since_commit: int | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "repo_name": self.repo_name,
            "score": self.score,
            "status": self.status.value,
            "vulnerabilities": self.vulnerabilities,
            "build_passing": self.build_passing,
            "days_since_commit": self.days_since_commit,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RepoHistoricalDataPoint:
        """Deserialize from dictionary."""
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            repo_name=data["repo_name"],
            score=data["score"],
            status=HealthStatus(data["status"]),
            vulnerabilities=data["vulnerabilities"],
            build_passing=data["build_passing"],
            days_since_commit=data["days_since_commit"],
        )

    @classmethod
    def from_repo_health(
        cls,
        repo: RepoHealth,
        timestamp: datetime | None = None,
    ) -> RepoHistoricalDataPoint:
        """Create from repo health."""
        from pulse.models import BuildStatus

        return cls(
            timestamp=timestamp or datetime.now(),
            repo_name=repo.name,
            score=repo.score,
            status=repo.status,
            vulnerabilities=(
                repo.vulnerability_report.total_alerts if repo.vulnerability_report else 0
            ),
            build_passing=repo.latest_build == BuildStatus.PASSING,
            days_since_commit=repo.days_since_commit,
        )


@dataclass
class TrendAnalysis:
    """Analysis of trend data."""

    metric_name: str
    current_value: float
    previous_value: float | None
    change: float
    change_percent: float
    direction: str  # "up", "down", "stable"
    period_days: int
    data_points: int

    @property
    def is_improving(self) -> bool:
        """Check if trend is improving.

        For most metrics, 'up' means improving.
        For vulnerabilities/issues, 'down' is improving.
        """
        improving_down = ["vulnerabilities", "critical_count", "open_issues"]
        if any(m in self.metric_name.lower() for m in improving_down):
            return self.direction == "down"
        return self.direction == "up"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "metric_name": self.metric_name,
            "current_value": self.current_value,
            "previous_value": self.previous_value,
            "change": self.change,
            "change_percent": round(self.change_percent, 2),
            "direction": self.direction,
            "period_days": self.period_days,
            "data_points": self.data_points,
            "is_improving": self.is_improving,
        }


class TrendStore:
    """Persistent storage for historical trend data.

    Stores historical data points in JSON Lines format for efficient
    appending and reading.

    Example:
        >>> store = TrendStore(Path("~/.pulse/history"))
        >>> store.save_summary(summary)
        >>> trends = store.analyze_trends(days=30)
    """

    def __init__(self, data_dir: Path | str) -> None:
        """Initialize trend store.

        Args:
            data_dir: Directory to store historical data.
        """
        self.data_dir = Path(data_dir).expanduser()
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Ensure data directory exists."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _summary_path(self, org: str) -> Path:
        """Get path for organization summary history."""
        return self.data_dir / f"{org}_summary.jsonl"

    def _repo_path(self, org: str) -> Path:
        """Get path for repository history."""
        return self.data_dir / f"{org}_repos.jsonl"

    def save_summary(self, summary: EcosystemSummary) -> None:
        """Save ecosystem summary to history.

        Args:
            summary: Summary to save.
        """
        data_point = HistoricalDataPoint.from_summary(summary)
        path = self._summary_path(summary.organization)

        with open(path, "a") as f:
            f.write(json.dumps(data_point.to_dict()) + "\n")

    def save_repo_data(
        self,
        org: str,
        repos: list[RepoHealth],
        timestamp: datetime | None = None,
    ) -> None:
        """Save repository data to history.

        Args:
            org: Organization name.
            repos: List of repository health data.
            timestamp: Optional timestamp (defaults to now).
        """
        ts = timestamp or datetime.now()
        path = self._repo_path(org)

        with open(path, "a") as f:
            for repo in repos:
                point = RepoHistoricalDataPoint.from_repo_health(repo, ts)
                f.write(json.dumps(point.to_dict()) + "\n")

    def load_summary_history(
        self,
        org: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[HistoricalDataPoint]:
        """Load summary history for organization.

        Args:
            org: Organization name.
            since: Start of time range.
            until: End of time range.

        Returns:
            List of historical data points.
        """
        path = self._summary_path(org)
        if not path.exists():
            return []

        points = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    point = HistoricalDataPoint.from_dict(json.loads(line))
                    if since and point.timestamp < since:
                        continue
                    if until and point.timestamp > until:
                        continue
                    points.append(point)
                except (json.JSONDecodeError, KeyError):
                    continue

        return sorted(points, key=lambda p: p.timestamp)

    def load_repo_history(
        self,
        org: str,
        repo_name: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[RepoHistoricalDataPoint]:
        """Load repository history.

        Args:
            org: Organization name.
            repo_name: Optional specific repository.
            since: Start of time range.
            until: End of time range.

        Returns:
            List of repository data points.
        """
        path = self._repo_path(org)
        if not path.exists():
            return []

        points = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    point = RepoHistoricalDataPoint.from_dict(json.loads(line))
                    if repo_name and point.repo_name != repo_name:
                        continue
                    if since and point.timestamp < since:
                        continue
                    if until and point.timestamp > until:
                        continue
                    points.append(point)
                except (json.JSONDecodeError, KeyError):
                    continue

        return sorted(points, key=lambda p: p.timestamp)

    def get_organizations(self) -> list[str]:
        """Get list of tracked organizations."""
        orgs = set()
        for path in self.data_dir.glob("*_summary.jsonl"):
            org = path.stem.replace("_summary", "")
            orgs.add(org)
        return sorted(orgs)

    def cleanup(self, org: str, keep_days: int = 365) -> int:
        """Remove data older than specified days.

        Args:
            org: Organization name.
            keep_days: Number of days to keep.

        Returns:
            Number of entries removed.
        """
        cutoff = datetime.now() - timedelta(days=keep_days)
        removed = 0

        for path in [self._summary_path(org), self._repo_path(org)]:
            if not path.exists():
                continue

            lines_to_keep = []
            with open(path) as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        ts = datetime.fromisoformat(data["timestamp"])
                        if ts >= cutoff:
                            lines_to_keep.append(line)
                        else:
                            removed += 1
                    except (json.JSONDecodeError, KeyError):
                        removed += 1

            with open(path, "w") as f:
                f.writelines(lines_to_keep)

        return removed


class TrendAnalyzer:
    """Analyzes historical trends from stored data.

    Example:
        >>> analyzer = TrendAnalyzer(store)
        >>> trends = analyzer.analyze_summary_trends("myorg", days=30)
        >>> for trend in trends:
        ...     print(f"{trend.metric_name}: {trend.direction}")
    """

    def __init__(self, store: TrendStore) -> None:
        """Initialize trend analyzer.

        Args:
            store: Trend data store.
        """
        self.store = store

    def analyze_summary_trends(
        self,
        org: str,
        days: int = 30,
    ) -> list[TrendAnalysis]:
        """Analyze ecosystem-level trends.

        Args:
            org: Organization name.
            days: Number of days to analyze.

        Returns:
            List of trend analyses for each metric.
        """
        since = datetime.now() - timedelta(days=days)
        history = self.store.load_summary_history(org, since=since)

        if len(history) < 2:
            return []

        trends = []

        # Analyze each metric
        metrics = [
            ("average_score", "Average Score"),
            ("healthy_count", "Healthy Repos"),
            ("warning_count", "Warning Repos"),
            ("critical_count", "Critical Repos"),
            ("total_vulnerabilities", "Vulnerabilities"),
            ("total_stars", "Total Stars"),
            ("total_open_issues", "Open Issues"),
        ]

        for attr, name in metrics:
            values = [getattr(p, attr) for p in history]
            trend = self._analyze_metric(name, values, days)
            if trend:
                trends.append(trend)

        return trends

    def analyze_repo_trends(
        self,
        org: str,
        repo_name: str,
        days: int = 30,
    ) -> list[TrendAnalysis]:
        """Analyze trends for a specific repository.

        Args:
            org: Organization name.
            repo_name: Repository name.
            days: Number of days to analyze.

        Returns:
            List of trend analyses.
        """
        since = datetime.now() - timedelta(days=days)
        history = self.store.load_repo_history(org, repo_name, since=since)

        if len(history) < 2:
            return []

        trends = []

        # Score trend
        scores = [p.score for p in history]
        trend = self._analyze_metric("Score", scores, days)
        if trend:
            trends.append(trend)

        # Vulnerability trend
        vulns = [p.vulnerabilities for p in history]
        trend = self._analyze_metric("Vulnerabilities", vulns, days)
        if trend:
            trends.append(trend)

        return trends

    def _analyze_metric(
        self,
        name: str,
        values: list[float | int],
        period_days: int,
    ) -> TrendAnalysis | None:
        """Analyze a single metric's trend.

        Args:
            name: Metric name.
            values: Historical values.
            period_days: Analysis period in days.

        Returns:
            Trend analysis or None if insufficient data.
        """
        if len(values) < 2:
            return None

        current = float(values[-1])
        previous = float(values[0])
        change = current - previous

        # Calculate percent change
        if previous != 0:
            change_percent = (change / abs(previous)) * 100
        else:
            change_percent = 100.0 if change > 0 else 0.0

        # Determine direction
        threshold = 0.01 * abs(previous) if previous != 0 else 0.1
        if abs(change) < threshold:
            direction = "stable"
        elif change > 0:
            direction = "up"
        else:
            direction = "down"

        return TrendAnalysis(
            metric_name=name,
            current_value=current,
            previous_value=previous,
            change=change,
            change_percent=change_percent,
            direction=direction,
            period_days=period_days,
            data_points=len(values),
        )

    def get_score_percentiles(
        self,
        org: str,
        repo_name: str,
        days: int = 90,
    ) -> dict[str, float]:
        """Get score percentiles for a repository.

        Args:
            org: Organization name.
            repo_name: Repository name.
            days: Number of days to analyze.

        Returns:
            Dictionary with percentile values.
        """
        since = datetime.now() - timedelta(days=days)
        history = self.store.load_repo_history(org, repo_name, since=since)

        scores = [p.score for p in history]
        if len(scores) < 3:
            return {}

        sorted_scores = sorted(scores)
        n = len(sorted_scores)

        return {
            "min": sorted_scores[0],
            "p25": sorted_scores[int(n * 0.25)],
            "median": sorted_scores[int(n * 0.50)],
            "p75": sorted_scores[int(n * 0.75)],
            "max": sorted_scores[-1],
            "mean": statistics.mean(scores),
            "stdev": statistics.stdev(scores) if len(scores) > 1 else 0.0,
        }

    def get_status_history(
        self,
        org: str,
        repo_name: str,
        days: int = 30,
    ) -> list[tuple[datetime, HealthStatus]]:
        """Get status change history for a repository.

        Args:
            org: Organization name.
            repo_name: Repository name.
            days: Number of days to analyze.

        Returns:
            List of (timestamp, status) tuples showing changes.
        """
        since = datetime.now() - timedelta(days=days)
        history = self.store.load_repo_history(org, repo_name, since=since)

        if not history:
            return []

        changes = []
        prev_status = None

        for point in history:
            if point.status != prev_status:
                changes.append((point.timestamp, point.status))
                prev_status = point.status

        return changes

    def compare_periods(
        self,
        org: str,
        period1_days: int = 7,
        period2_days: int = 7,
    ) -> dict[str, dict[str, float]]:
        """Compare two time periods.

        Args:
            org: Organization name.
            period1_days: Recent period length.
            period2_days: Previous period length.

        Returns:
            Comparison of metrics between periods.
        """
        now = datetime.now()
        period1_start = now - timedelta(days=period1_days)
        period2_start = now - timedelta(days=period1_days + period2_days)
        period2_end = period1_start

        period1_data = self.store.load_summary_history(org, since=period1_start, until=now)
        period2_data = self.store.load_summary_history(org, since=period2_start, until=period2_end)

        if not period1_data or not period2_data:
            return {}

        # Calculate averages for each period
        def avg_metric(data: list[HistoricalDataPoint], attr: str) -> float:
            values = [getattr(p, attr) for p in data]
            return statistics.mean(values) if values else 0.0

        metrics = [
            "average_score",
            "healthy_count",
            "warning_count",
            "critical_count",
            "total_vulnerabilities",
        ]

        comparison = {}
        for metric in metrics:
            p1_avg = avg_metric(period1_data, metric)
            p2_avg = avg_metric(period2_data, metric)
            change = p1_avg - p2_avg
            change_pct = ((change / p2_avg) * 100) if p2_avg != 0 else 0

            comparison[metric] = {
                "period1": round(p1_avg, 2),
                "period2": round(p2_avg, 2),
                "change": round(change, 2),
                "change_percent": round(change_pct, 2),
            }

        return comparison

    def generate_report(
        self,
        org: str,
        days: int = 30,
    ) -> dict[str, Any]:
        """Generate comprehensive trend report.

        Args:
            org: Organization name.
            days: Analysis period.

        Returns:
            Complete trend report.
        """
        trends = self.analyze_summary_trends(org, days)
        comparison = self.compare_periods(org, days // 2, days // 2)
        history = self.store.load_summary_history(org, since=datetime.now() - timedelta(days=days))

        return {
            "organization": org,
            "analysis_period_days": days,
            "generated_at": datetime.now().isoformat(),
            "data_points": len(history),
            "trends": [t.to_dict() for t in trends],
            "period_comparison": comparison,
            "summary": {
                "improving_metrics": sum(1 for t in trends if t.is_improving),
                "declining_metrics": sum(
                    1 for t in trends if not t.is_improving and t.direction != "stable"
                ),
                "stable_metrics": sum(1 for t in trends if t.direction == "stable"),
            },
        }
