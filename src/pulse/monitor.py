"""Core ecosystem monitoring functionality."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from pulse.config import PulseConfig
from pulse.github import GitHubClient, GitHubAPIError, RateLimitExceeded
from pulse.models import EcosystemSummary, HealthStatus, RepoHealth


class MonitorError(Exception):
    """Monitoring error."""

    pass


class EcosystemMonitor:
    """Monitor ecosystem health across repositories.

    Provides comprehensive monitoring of repository health, security
    vulnerabilities, build status, and quality metrics.

    Example:
        >>> config = PulseConfig.load()
        >>> monitor = EcosystemMonitor(config)
        >>> summary = await monitor.scan_all()
        >>> print(f"Health: {summary.health_percentage}%")
    """

    def __init__(
        self,
        config: PulseConfig | None = None,
        org: str | None = None,
    ) -> None:
        """Initialize the ecosystem monitor.

        Args:
            config: Pulse configuration. If None, loads default config.
            org: Organization name override.
        """
        self.config = config or PulseConfig.load()
        if org:
            self.config.github.organization = org

        self._client: GitHubClient | None = None
        self._summary: EcosystemSummary | None = None
        self._progress_callback: Callable[[str, int, int], None] | None = None

    @property
    def organization(self) -> str:
        """Get the organization being monitored."""
        return self.config.github.organization

    @property
    def summary(self) -> EcosystemSummary | None:
        """Get the latest scan summary."""
        return self._summary

    def set_progress_callback(
        self, callback: Callable[[str, int, int], None]
    ) -> None:
        """Set progress callback for scan updates.

        Args:
            callback: Function called with (repo_name, current, total).
        """
        self._progress_callback = callback

    def _report_progress(self, repo_name: str, current: int, total: int) -> None:
        """Report scan progress."""
        if self._progress_callback:
            self._progress_callback(repo_name, current, total)

    async def _get_client(self) -> GitHubClient:
        """Get or create GitHub client."""
        if self._client is None:
            self._client = GitHubClient(self.config)
        return self._client

    async def close(self) -> None:
        """Close the monitor and release resources."""
        if self._client:
            await self._client.close()
            self._client = None

    async def __aenter__(self) -> EcosystemMonitor:
        """Enter async context."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()

    def _should_include_repo(self, repo_data: dict[str, Any]) -> bool:
        """Check if repository should be included in scan.

        Args:
            repo_data: Repository data from GitHub API.

        Returns:
            True if repo should be included.
        """
        monitoring = self.config.monitoring

        # Check archived
        if repo_data.get("archived", False) and not monitoring.include_archived:
            return False

        # Check forks
        if repo_data.get("fork", False) and not monitoring.include_forks:
            return False

        # Check private
        if repo_data.get("private", False) and not monitoring.include_private:
            return False

        # Check language filter
        if monitoring.languages:
            repo_lang = (repo_data.get("language") or "").lower()
            if repo_lang and repo_lang not in [l.lower() for l in monitoring.languages]:
                return False

        return True

    async def scan_all(self) -> EcosystemSummary:
        """Scan all repositories in the organization.

        Returns:
            EcosystemSummary with health information for all repos.

        Raises:
            MonitorError: If scan fails.
        """
        client = await self._get_client()

        try:
            async with client:
                # Fetch all repositories
                repos = await client.get_repositories()

                # Filter repositories
                filtered_repos = [r for r in repos if self._should_include_repo(r)]

                # Apply max repos limit
                if self.config.monitoring.max_repos:
                    filtered_repos = filtered_repos[: self.config.monitoring.max_repos]

                # Create summary
                summary = EcosystemSummary(organization=self.organization)

                # Scan each repository
                total = len(filtered_repos)
                for i, repo_data in enumerate(filtered_repos, 1):
                    repo_name = repo_data["name"]
                    self._report_progress(repo_name, i, total)

                    try:
                        health = await client.build_repo_health(repo_data)
                        summary.add_repo(health)
                    except RateLimitExceeded as e:
                        raise MonitorError(
                            f"Rate limit exceeded. Resets at: {e.reset_at}"
                        ) from e
                    except GitHubAPIError as e:
                        # Log error but continue with other repos
                        health = RepoHealth(
                            name=repo_name,
                            full_name=repo_data["full_name"],
                            url=repo_data["html_url"],
                            status=HealthStatus.UNKNOWN,
                        )
                        summary.add_repo(health)

                self._summary = summary
                return summary

        except RateLimitExceeded as e:
            raise MonitorError(
                f"GitHub rate limit exceeded. Resets at: {e.reset_at}"
            ) from e
        except GitHubAPIError as e:
            raise MonitorError(f"GitHub API error: {e}") from e

    async def scan_repo(self, repo_name: str) -> RepoHealth:
        """Scan a single repository.

        Args:
            repo_name: Repository name.

        Returns:
            RepoHealth for the repository.

        Raises:
            MonitorError: If scan fails.
        """
        client = await self._get_client()

        try:
            async with client:
                repo_data = await client.get_repository(repo_name)
                return await client.build_repo_health(repo_data)
        except GitHubAPIError as e:
            raise MonitorError(f"Failed to scan {repo_name}: {e}") from e

    async def scan_repos(self, repo_names: list[str]) -> EcosystemSummary:
        """Scan specific repositories.

        Args:
            repo_names: List of repository names to scan.

        Returns:
            EcosystemSummary for the specified repos.

        Raises:
            MonitorError: If scan fails.
        """
        client = await self._get_client()
        summary = EcosystemSummary(organization=self.organization)

        try:
            async with client:
                total = len(repo_names)
                for i, repo_name in enumerate(repo_names, 1):
                    self._report_progress(repo_name, i, total)

                    try:
                        repo_data = await client.get_repository(repo_name)
                        health = await client.build_repo_health(repo_data)
                        summary.add_repo(health)
                    except GitHubAPIError:
                        health = RepoHealth(
                            name=repo_name,
                            full_name=f"{self.organization}/{repo_name}",
                            url=f"https://github.com/{self.organization}/{repo_name}",
                            status=HealthStatus.UNKNOWN,
                        )
                        summary.add_repo(health)

        except RateLimitExceeded as e:
            raise MonitorError(
                f"GitHub rate limit exceeded. Resets at: {e.reset_at}"
            ) from e

        self._summary = summary
        return summary

    def get_critical_repos(self) -> list[RepoHealth]:
        """Get repositories with critical status.

        Returns:
            List of repos with critical health status.
        """
        if not self._summary:
            return []
        return [r for r in self._summary.repos if r.status == HealthStatus.CRITICAL]

    def get_repos_needing_attention(self) -> list[RepoHealth]:
        """Get repositories that need attention.

        Returns:
            List of repos with warning or critical status.
        """
        if not self._summary:
            return []
        return [r for r in self._summary.repos if r.needs_attention]

    def get_vulnerable_repos(self) -> list[RepoHealth]:
        """Get repositories with security vulnerabilities.

        Returns:
            List of repos with open vulnerabilities.
        """
        if not self._summary:
            return []
        return [
            r
            for r in self._summary.repos
            if r.vulnerability_report and r.vulnerability_report.total_alerts > 0
        ]

    def get_failing_builds(self) -> list[RepoHealth]:
        """Get repositories with failing builds.

        Returns:
            List of repos with failing CI builds.
        """
        if not self._summary:
            return []
        from pulse.models import BuildStatus

        return [
            r for r in self._summary.repos if r.latest_build == BuildStatus.FAILING
        ]

    def get_stale_repos(self, days: int = 90) -> list[RepoHealth]:
        """Get repositories with no recent commits.

        Args:
            days: Number of days to consider stale.

        Returns:
            List of repos with no commits in specified days.
        """
        if not self._summary:
            return []
        return [
            r
            for r in self._summary.repos
            if r.days_since_commit is not None and r.days_since_commit > days
        ]

    def export_json(self, path: Path | str) -> None:
        """Export summary to JSON file.

        Args:
            path: Output file path.
        """
        if not self._summary:
            raise MonitorError("No scan data available. Run scan_all() first.")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "summary": self._summary.to_dict(),
            "repos": [
                {
                    "name": r.name,
                    "full_name": r.full_name,
                    "url": r.url,
                    "status": r.status.value,
                    "score": round(r.score, 1),
                    "language": r.language.value,
                    "last_commit": r.last_commit.isoformat() if r.last_commit else None,
                    "days_since_commit": r.days_since_commit,
                    "build_status": r.latest_build.value,
                    "stars": r.metrics.stars,
                    "open_issues": r.metrics.open_issues,
                    "vulnerabilities": (
                        r.vulnerability_report.total_alerts
                        if r.vulnerability_report
                        else 0
                    ),
                    "critical_vulns": (
                        r.vulnerability_report.critical_count
                        if r.vulnerability_report
                        else 0
                    ),
                }
                for r in self._summary.repos
            ],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def export_markdown(self, path: Path | str) -> None:
        """Export summary to Markdown file.

        Args:
            path: Output file path.
        """
        if not self._summary:
            raise MonitorError("No scan data available. Run scan_all() first.")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            f"# Ecosystem Health Report",
            f"",
            f"**Organization:** {self._summary.organization}",
            f"**Generated:** {self._summary.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Repositories | {self._summary.total_repos} |",
            f"| Healthy | {self._summary.healthy_count} |",
            f"| Warning | {self._summary.warning_count} |",
            f"| Critical | {self._summary.critical_count} |",
            f"| Average Score | {self._summary.average_score:.1f}/100 |",
            f"| Total Stars | {self._summary.total_stars} |",
            f"| Open Issues | {self._summary.total_open_issues} |",
            f"| Vulnerabilities | {self._summary.total_vulnerabilities} |",
            f"",
            f"## Repository Details",
            f"",
            f"| Repository | Status | Score | Build | Vulns |",
            f"|------------|--------|-------|-------|-------|",
        ]

        for repo in sorted(self._summary.repos, key=lambda r: -r.score):
            status_emoji = {
                HealthStatus.HEALTHY: "🟢",
                HealthStatus.WARNING: "🟡",
                HealthStatus.CRITICAL: "🔴",
                HealthStatus.UNKNOWN: "⚪",
            }.get(repo.status, "⚪")

            vulns = (
                repo.vulnerability_report.total_alerts
                if repo.vulnerability_report
                else 0
            )

            lines.append(
                f"| [{repo.name}]({repo.url}) | {status_emoji} {repo.status.value} | "
                f"{repo.score:.0f} | {repo.latest_build.value} | {vulns} |"
            )

        # Add critical issues section
        critical = self.get_critical_repos()
        if critical:
            lines.extend(
                [
                    f"",
                    f"## Critical Issues",
                    f"",
                ]
            )
            for repo in critical:
                lines.append(f"- **{repo.name}**: Score {repo.score:.0f}/100")

        # Add vulnerability section
        vulnerable = self.get_vulnerable_repos()
        if vulnerable:
            lines.extend(
                [
                    f"",
                    f"## Security Vulnerabilities",
                    f"",
                ]
            )
            for repo in vulnerable:
                if repo.vulnerability_report:
                    vr = repo.vulnerability_report
                    lines.append(
                        f"- **{repo.name}**: {vr.total_alerts} alerts "
                        f"({vr.critical_count} critical, {vr.high_count} high)"
                    )

        with open(path, "w") as f:
            f.write("\n".join(lines))


def run_scan(
    org: str | None = None,
    config_path: str | None = None,
) -> EcosystemSummary:
    """Synchronous wrapper to run ecosystem scan.

    Args:
        org: Organization name override.
        config_path: Path to config file.

    Returns:
        EcosystemSummary with scan results.
    """
    config = PulseConfig.load(config_path)

    async def _run() -> EcosystemSummary:
        async with EcosystemMonitor(config, org) as monitor:
            return await monitor.scan_all()

    return asyncio.run(_run())
