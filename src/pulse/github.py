"""GitHub API client for Pulse."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import httpx

from pulse.config import PulseConfig
from pulse.models import (
    BuildStatus,
    CIStatus,
    HealthStatus,
    Language,
    RepoHealth,
    RepoMetrics,
    SecurityAlert,
    Severity,
    VulnerabilityReport,
)


class GitHubAPIError(Exception):
    """GitHub API error."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class RateLimitExceeded(GitHubAPIError):
    """Rate limit exceeded error."""

    def __init__(self, reset_at: datetime | None = None) -> None:
        super().__init__("GitHub API rate limit exceeded", status_code=403)
        self.reset_at = reset_at


class GitHubClient:
    """Async GitHub API client."""

    LANGUAGE_MAP: dict[str, Language] = {
        "rust": Language.RUST,
        "python": Language.PYTHON,
        "javascript": Language.JAVASCRIPT,
        "typescript": Language.TYPESCRIPT,
        "html": Language.HTML,
        "shell": Language.SHELL,
    }

    def __init__(self, config: PulseConfig) -> None:
        """Initialize GitHub client.

        Args:
            config: Pulse configuration.
        """
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._rate_limit_remaining: int = 5000
        self._rate_limit_reset: datetime | None = None

    async def __aenter__(self) -> GitHubClient:
        """Enter async context."""
        await self._ensure_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure HTTP client is initialized."""
        if self._client is None or self._client.is_closed:
            token = self.config.get_github_token()
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Pulse-Ecosystem-Monitor/0.0.1",
            }
            if token:
                headers["Authorization"] = f"Bearer {token}"

            self._client = httpx.AsyncClient(
                base_url=self.config.github.api_url,
                headers=headers,
                timeout=30.0,
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _update_rate_limit(self, response: httpx.Response) -> None:
        """Update rate limit info from response headers."""
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset = response.headers.get("X-RateLimit-Reset")

        if remaining:
            self._rate_limit_remaining = int(remaining)
        if reset:
            self._rate_limit_reset = datetime.fromtimestamp(int(reset))

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> dict[str, Any] | list[Any]:
        """Make API request with rate limit handling.

        Args:
            method: HTTP method.
            path: API path.
            **kwargs: Additional request arguments.

        Returns:
            JSON response data.

        Raises:
            RateLimitExceeded: If rate limit is exceeded.
            GitHubAPIError: If API request fails.
        """
        # Check rate limit buffer
        if self._rate_limit_remaining <= self.config.github.rate_limit_buffer:
            raise RateLimitExceeded(self._rate_limit_reset)

        client = await self._ensure_client()
        response = await client.request(method, path, **kwargs)

        self._update_rate_limit(response)

        if response.status_code == 403:
            if "rate limit" in response.text.lower():
                raise RateLimitExceeded(self._rate_limit_reset)
            raise GitHubAPIError(f"Forbidden: {response.text}", 403)

        if response.status_code == 404:
            raise GitHubAPIError(f"Not found: {path}", 404)

        if response.status_code >= 400:
            raise GitHubAPIError(
                f"API error: {response.status_code} - {response.text}",
                response.status_code,
            )

        return response.json()

    async def get_repositories(self) -> list[dict[str, Any]]:
        """Get all repositories for the organization.

        Returns:
            List of repository data.
        """
        org = self.config.github.organization
        repos: list[dict[str, Any]] = []
        page = 1
        per_page = 100

        while True:
            data = await self._request(
                "GET",
                f"/orgs/{org}/repos",
                params={"page": page, "per_page": per_page, "type": "all"},
            )

            if not data:
                break

            assert isinstance(data, list)
            repos.extend(data)

            if len(data) < per_page:
                break

            page += 1

            # Respect rate limiting
            if self._rate_limit_remaining < self.config.github.rate_limit_buffer * 2:
                await asyncio.sleep(1)

        return repos

    async def get_repository(self, repo_name: str) -> dict[str, Any]:
        """Get single repository details.

        Args:
            repo_name: Repository name.

        Returns:
            Repository data.
        """
        org = self.config.github.organization
        data = await self._request("GET", f"/repos/{org}/{repo_name}")
        assert isinstance(data, dict)
        return data

    async def get_latest_commit(self, repo_name: str, branch: str = "main") -> dict[str, Any] | None:
        """Get latest commit on a branch.

        Args:
            repo_name: Repository name.
            branch: Branch name.

        Returns:
            Commit data or None if not found.
        """
        org = self.config.github.organization
        try:
            data = await self._request(
                "GET", f"/repos/{org}/{repo_name}/commits/{branch}"
            )
            assert isinstance(data, dict)
            return data
        except GitHubAPIError:
            return None

    async def get_workflow_runs(
        self, repo_name: str, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Get recent workflow runs.

        Args:
            repo_name: Repository name.
            limit: Maximum number of runs to fetch.

        Returns:
            List of workflow run data.
        """
        org = self.config.github.organization
        try:
            data = await self._request(
                "GET",
                f"/repos/{org}/{repo_name}/actions/runs",
                params={"per_page": limit},
            )
            assert isinstance(data, dict)
            return data.get("workflow_runs", [])
        except GitHubAPIError:
            return []

    async def get_vulnerability_alerts(self, repo_name: str) -> list[dict[str, Any]]:
        """Get Dependabot vulnerability alerts.

        Args:
            repo_name: Repository name.

        Returns:
            List of vulnerability alerts.
        """
        org = self.config.github.organization
        try:
            data = await self._request(
                "GET",
                f"/repos/{org}/{repo_name}/dependabot/alerts",
                params={"state": "open", "per_page": 100},
            )
            assert isinstance(data, list)
            return data
        except GitHubAPIError:
            return []

    async def get_releases(self, repo_name: str, limit: int = 1) -> list[dict[str, Any]]:
        """Get repository releases.

        Args:
            repo_name: Repository name.
            limit: Maximum number of releases to fetch.

        Returns:
            List of release data.
        """
        org = self.config.github.organization
        try:
            data = await self._request(
                "GET",
                f"/repos/{org}/{repo_name}/releases",
                params={"per_page": limit},
            )
            assert isinstance(data, list)
            return data
        except GitHubAPIError:
            return []

    async def get_contents(self, repo_name: str, path: str) -> dict[str, Any] | None:
        """Get file/directory contents.

        Args:
            repo_name: Repository name.
            path: File or directory path.

        Returns:
            Contents data or None if not found.
        """
        org = self.config.github.organization
        try:
            data = await self._request("GET", f"/repos/{org}/{repo_name}/contents/{path}")
            assert isinstance(data, dict)
            return data
        except GitHubAPIError:
            return None

    def _parse_datetime(self, dt_str: str | None) -> datetime | None:
        """Parse ISO datetime string."""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _map_language(self, lang: str | None) -> Language:
        """Map GitHub language to Language enum."""
        if not lang:
            return Language.OTHER
        return self.LANGUAGE_MAP.get(lang.lower(), Language.OTHER)

    def _map_severity(self, severity: str) -> Severity:
        """Map GitHub severity to Severity enum."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "moderate": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return severity_map.get(severity.lower(), Severity.INFO)

    def _map_build_status(self, status: str | None, conclusion: str | None) -> BuildStatus:
        """Map GitHub workflow status to BuildStatus."""
        if status == "completed":
            if conclusion == "success":
                return BuildStatus.PASSING
            elif conclusion in ("failure", "cancelled"):
                return BuildStatus.FAILING
        elif status in ("queued", "in_progress"):
            return BuildStatus.PENDING
        return BuildStatus.UNKNOWN

    async def build_repo_health(self, repo_data: dict[str, Any]) -> RepoHealth:
        """Build RepoHealth from repository data.

        Args:
            repo_data: Raw repository data from API.

        Returns:
            RepoHealth instance.
        """
        repo_name = repo_data["name"]

        # Basic info
        health = RepoHealth(
            name=repo_name,
            full_name=repo_data["full_name"],
            url=repo_data["html_url"],
            description=repo_data.get("description"),
            language=self._map_language(repo_data.get("language")),
            default_branch=repo_data.get("default_branch", "main"),
            created_at=self._parse_datetime(repo_data.get("created_at")),
            updated_at=self._parse_datetime(repo_data.get("updated_at")),
        )

        # Metrics
        health.metrics = RepoMetrics(
            stars=repo_data.get("stargazers_count", 0),
            forks=repo_data.get("forks_count", 0),
            open_issues=repo_data.get("open_issues_count", 0),
            watchers=repo_data.get("watchers_count", 0),
            size_kb=repo_data.get("size", 0),
        )

        # Fetch additional data concurrently
        tasks = [
            self.get_latest_commit(repo_name, health.default_branch),
            self.get_workflow_runs(repo_name, limit=5),
            self.get_vulnerability_alerts(repo_name),
            self.get_releases(repo_name, limit=1),
            self.get_contents(repo_name, "README.md"),
            self.get_contents(repo_name, "LICENSE"),
            self.get_contents(repo_name, ".github/workflows"),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process commit info
        commit_data = results[0]
        if isinstance(commit_data, dict):
            commit_info = commit_data.get("commit", {})
            author_info = commit_info.get("author", {})
            health.last_commit = self._parse_datetime(author_info.get("date"))

        # Process workflow runs
        workflow_runs = results[1]
        if isinstance(workflow_runs, list):
            for run in workflow_runs:
                ci_status = CIStatus(
                    workflow_name=run.get("name", "Unknown"),
                    status=self._map_build_status(
                        run.get("status"), run.get("conclusion")
                    ),
                    conclusion=run.get("conclusion"),
                    run_url=run.get("html_url"),
                    started_at=self._parse_datetime(run.get("run_started_at")),
                    completed_at=self._parse_datetime(run.get("updated_at")),
                )
                health.ci_status.append(ci_status)

            # Set latest build status
            if health.ci_status:
                health.latest_build = health.ci_status[0].status

        # Process vulnerabilities
        alerts_data = results[2]
        if isinstance(alerts_data, list):
            alerts = []
            for alert in alerts_data:
                security_alert = SecurityAlert(
                    id=str(alert.get("number", "")),
                    package=alert.get("dependency", {}).get("package", {}).get("name", "unknown"),
                    severity=self._map_severity(
                        alert.get("security_advisory", {}).get("severity", "info")
                    ),
                    title=alert.get("security_advisory", {}).get("summary", ""),
                    description=alert.get("security_advisory", {}).get("description", ""),
                    cve_id=alert.get("security_advisory", {}).get("cve_id"),
                    patched_version=alert.get("security_vulnerability", {}).get(
                        "first_patched_version", {}
                    ).get("identifier"),
                    advisory_url=alert.get("security_advisory", {}).get("references", [{}])[0].get("url") if alert.get("security_advisory", {}).get("references") else None,
                    created_at=self._parse_datetime(alert.get("created_at")),
                )
                alerts.append(security_alert)

            health.vulnerability_report = VulnerabilityReport(
                repo_name=repo_name,
                total_alerts=len(alerts),
                critical_count=sum(1 for a in alerts if a.severity == Severity.CRITICAL),
                high_count=sum(1 for a in alerts if a.severity == Severity.HIGH),
                medium_count=sum(1 for a in alerts if a.severity == Severity.MEDIUM),
                low_count=sum(1 for a in alerts if a.severity == Severity.LOW),
                alerts=alerts,
                last_scanned=datetime.now(),
            )

        # Process releases
        releases_data = results[3]
        if isinstance(releases_data, list) and releases_data:
            health.last_release = self._parse_datetime(
                releases_data[0].get("published_at")
            )

        # Check for documentation/quality files
        health.has_readme = results[4] is not None and not isinstance(results[4], Exception)
        health.has_license = results[5] is not None and not isinstance(results[5], Exception)
        health.has_ci = results[6] is not None and not isinstance(results[6], Exception)
        health.has_tests = True  # Would need additional check
        health.has_docs = health.has_readme

        # Calculate overall health score
        health.calculate_score()

        # Determine status
        if health.score >= 80:
            health.status = HealthStatus.HEALTHY
        elif health.score >= 50:
            health.status = HealthStatus.WARNING
        elif health.score > 0:
            health.status = HealthStatus.CRITICAL
        else:
            health.status = HealthStatus.UNKNOWN

        return health

    @property
    def rate_limit_remaining(self) -> int:
        """Get remaining rate limit."""
        return self._rate_limit_remaining

    @property
    def rate_limit_reset(self) -> datetime | None:
        """Get rate limit reset time."""
        return self._rate_limit_reset
