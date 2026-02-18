"""Data models for Pulse ecosystem monitoring."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class HealthStatus(str, Enum):
    """Repository health status levels."""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Security vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Language(str, Enum):
    """Supported programming languages."""

    RUST = "rust"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    HTML = "html"
    SHELL = "shell"
    OTHER = "other"


class BuildStatus(str, Enum):
    """CI/CD build status."""

    PASSING = "passing"
    FAILING = "failing"
    PENDING = "pending"
    UNKNOWN = "unknown"


class CIStatus(BaseModel):
    """CI/CD pipeline status."""

    workflow_name: str
    status: BuildStatus
    conclusion: str | None = None
    run_url: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class DependencyInfo(BaseModel):
    """Dependency information."""

    name: str
    version: str
    latest_version: str | None = None
    is_outdated: bool = False
    has_vulnerability: bool = False


class SecurityAlert(BaseModel):
    """Security vulnerability alert."""

    id: str
    package: str
    severity: Severity
    title: str
    description: str
    cve_id: str | None = None
    patched_version: str | None = None
    advisory_url: str | None = None
    created_at: datetime | None = None


class VulnerabilityReport(BaseModel):
    """Aggregated vulnerability report."""

    repo_name: str
    total_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    alerts: list[SecurityAlert] = Field(default_factory=list)
    last_scanned: datetime | None = None

    @property
    def has_critical(self) -> bool:
        """Check if there are critical vulnerabilities."""
        return self.critical_count > 0

    @property
    def severity_score(self) -> float:
        """Calculate weighted severity score (0-100, lower is better)."""
        return min(
            100.0,
            (self.critical_count * 40)
            + (self.high_count * 20)
            + (self.medium_count * 5)
            + (self.low_count * 1),
        )


class RepoMetrics(BaseModel):
    """Repository metrics and statistics."""

    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    open_prs: int = 0
    watchers: int = 0
    size_kb: int = 0
    contributors_count: int = 0


class RepoHealth(BaseModel):
    """Complete repository health assessment."""

    name: str
    full_name: str
    url: str
    description: str | None = None
    language: Language = Language.OTHER
    default_branch: str = "main"

    # Status indicators
    status: HealthStatus = HealthStatus.UNKNOWN
    score: float = Field(default=0.0, ge=0.0, le=100.0)

    # Timestamps
    last_commit: datetime | None = None
    last_release: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    # Metrics
    metrics: RepoMetrics = Field(default_factory=RepoMetrics)

    # CI/CD status
    ci_status: list[CIStatus] = Field(default_factory=list)
    latest_build: BuildStatus = BuildStatus.UNKNOWN

    # Security
    vulnerability_report: VulnerabilityReport | None = None

    # Dependencies
    dependencies: list[DependencyInfo] = Field(default_factory=list)
    outdated_deps_count: int = 0

    # Quality indicators
    has_readme: bool = False
    has_license: bool = False
    has_ci: bool = False
    has_tests: bool = False
    has_docs: bool = False

    @property
    def is_healthy(self) -> bool:
        """Check if repository is in healthy state."""
        return self.status == HealthStatus.HEALTHY

    @property
    def needs_attention(self) -> bool:
        """Check if repository needs attention."""
        return self.status in (HealthStatus.WARNING, HealthStatus.CRITICAL)

    @property
    def days_since_commit(self) -> int | None:
        """Calculate days since last commit."""
        if self.last_commit:
            delta = datetime.now() - self.last_commit.replace(tzinfo=None)
            return delta.days
        return None

    def calculate_score(self) -> float:
        """Calculate overall health score (0-100)."""
        score = 50.0  # Base score

        # Build status (+/- 15)
        if self.latest_build == BuildStatus.PASSING:
            score += 15
        elif self.latest_build == BuildStatus.FAILING:
            score -= 15

        # Documentation (+10)
        if self.has_readme:
            score += 5
        if self.has_docs:
            score += 5

        # Quality indicators (+15)
        if self.has_license:
            score += 5
        if self.has_ci:
            score += 5
        if self.has_tests:
            score += 5

        # Security (-20 max)
        if self.vulnerability_report:
            score -= min(20, self.vulnerability_report.severity_score / 5)

        # Activity (+10)
        days = self.days_since_commit
        if days is not None:
            if days <= 30:
                score += 10
            elif days <= 90:
                score += 5
            elif days > 365:
                score -= 10

        # Outdated dependencies (-10)
        if self.outdated_deps_count > 5:
            score -= 10
        elif self.outdated_deps_count > 0:
            score -= 5

        self.score = max(0.0, min(100.0, score))
        return self.score


class EcosystemSummary(BaseModel):
    """Summary of the entire ecosystem health."""

    organization: str
    total_repos: int = 0
    healthy_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    unknown_count: int = 0

    # Aggregated metrics
    total_stars: int = 0
    total_forks: int = 0
    total_open_issues: int = 0

    # Security overview
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0

    # Language distribution
    language_breakdown: dict[str, int] = Field(default_factory=dict)

    # Overall score
    average_score: float = 0.0

    # Timestamps
    generated_at: datetime = Field(default_factory=datetime.now)

    # Repository list
    repos: list[RepoHealth] = Field(default_factory=list)

    def add_repo(self, repo: RepoHealth) -> None:
        """Add a repository to the summary."""
        self.repos.append(repo)
        self.total_repos += 1

        # Update status counts
        if repo.status == HealthStatus.HEALTHY:
            self.healthy_count += 1
        elif repo.status == HealthStatus.WARNING:
            self.warning_count += 1
        elif repo.status == HealthStatus.CRITICAL:
            self.critical_count += 1
        else:
            self.unknown_count += 1

        # Update metrics
        self.total_stars += repo.metrics.stars
        self.total_forks += repo.metrics.forks
        self.total_open_issues += repo.metrics.open_issues

        # Update security
        if repo.vulnerability_report:
            self.total_vulnerabilities += repo.vulnerability_report.total_alerts
            self.critical_vulnerabilities += repo.vulnerability_report.critical_count

        # Update language breakdown
        lang = repo.language.value
        self.language_breakdown[lang] = self.language_breakdown.get(lang, 0) + 1

        # Recalculate average score
        if self.total_repos > 0:
            total_score = sum(r.score for r in self.repos)
            self.average_score = total_score / self.total_repos

    @property
    def health_percentage(self) -> float:
        """Calculate percentage of healthy repos."""
        if self.total_repos == 0:
            return 0.0
        return (self.healthy_count / self.total_repos) * 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "organization": self.organization,
            "total_repos": self.total_repos,
            "healthy_count": self.healthy_count,
            "warning_count": self.warning_count,
            "critical_count": self.critical_count,
            "health_percentage": round(self.health_percentage, 1),
            "average_score": round(self.average_score, 1),
            "total_stars": self.total_stars,
            "total_forks": self.total_forks,
            "total_open_issues": self.total_open_issues,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_vulnerabilities": self.critical_vulnerabilities,
            "language_breakdown": self.language_breakdown,
            "generated_at": self.generated_at.isoformat(),
        }
