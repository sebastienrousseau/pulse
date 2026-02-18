"""Tests for Pulse GitHub API client."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from pulse.config import PulseConfig
from pulse.github import (
    GitHubAPIError,
    GitHubClient,
    RateLimitExceeded,
)
from pulse.models import BuildStatus, Language, Severity


class TestGitHubAPIError:
    """Tests for GitHubAPIError."""

    def test_github_api_error(self) -> None:
        """Test GitHubAPIError creation."""
        error = GitHubAPIError("Test error", 404)
        assert str(error) == "Test error"
        assert error.status_code == 404

    def test_github_api_error_no_status(self) -> None:
        """Test GitHubAPIError without status code."""
        error = GitHubAPIError("Test error")
        assert str(error) == "Test error"
        assert error.status_code is None


class TestRateLimitExceeded:
    """Tests for RateLimitExceeded."""

    def test_rate_limit_exceeded(self) -> None:
        """Test RateLimitExceeded creation."""
        reset_time = datetime.now()
        error = RateLimitExceeded(reset_time)
        assert "rate limit" in str(error).lower()
        assert error.status_code == 403
        assert error.reset_at == reset_time

    def test_rate_limit_exceeded_no_reset(self) -> None:
        """Test RateLimitExceeded without reset time."""
        error = RateLimitExceeded()
        assert error.reset_at is None


class TestGitHubClient:
    """Tests for GitHubClient."""

    @pytest.fixture
    def config(self) -> PulseConfig:
        """Create test config."""
        config = PulseConfig()
        config.github.token = "test-token"
        return config

    @pytest.fixture
    def client(self, config: PulseConfig) -> GitHubClient:
        """Create GitHub client."""
        return GitHubClient(config)

    def test_init(self, config: PulseConfig) -> None:
        """Test client initialization."""
        client = GitHubClient(config)
        assert client.config == config
        assert client._client is None
        assert client._rate_limit_remaining == 5000

    @pytest.mark.asyncio
    async def test_context_manager(self, client: GitHubClient) -> None:
        """Test async context manager."""
        async with client as c:
            assert c is client

    @pytest.mark.asyncio
    async def test_close(self, client: GitHubClient) -> None:
        """Test closing client."""
        # Should not raise even without client
        await client.close()

    @pytest.mark.asyncio
    async def test_ensure_client(self, client: GitHubClient) -> None:
        """Test _ensure_client creates HTTP client."""
        http_client = await client._ensure_client()
        assert http_client is not None
        assert isinstance(http_client, httpx.AsyncClient)
        await client.close()

    @pytest.mark.asyncio
    async def test_ensure_client_with_token(self, config: PulseConfig) -> None:
        """Test _ensure_client includes auth header."""
        config.github.token = "my-secret-token"
        client = GitHubClient(config)

        http_client = await client._ensure_client()
        assert "Authorization" in http_client.headers
        assert "Bearer" in http_client.headers["Authorization"]
        await client.close()

    @pytest.mark.asyncio
    async def test_ensure_client_without_token(self) -> None:
        """Test _ensure_client without token."""
        import os
        # Temporarily clear env vars
        old_tokens = {}
        for var in ["GITHUB_TOKEN", "GH_TOKEN", "PULSE_GITHUB_TOKEN"]:
            old_tokens[var] = os.environ.pop(var, None)

        try:
            config = PulseConfig()
            config.github.token = None
            client = GitHubClient(config)

            http_client = await client._ensure_client()
            assert "Authorization" not in http_client.headers
            await client.close()
        finally:
            # Restore env vars
            for var, val in old_tokens.items():
                if val is not None:
                    os.environ[var] = val

    def test_update_rate_limit(self, client: GitHubClient) -> None:
        """Test rate limit update from response headers."""
        response = MagicMock()
        response.headers = {
            "X-RateLimit-Remaining": "4500",
            "X-RateLimit-Reset": "1700000000",
        }

        client._update_rate_limit(response)
        assert client._rate_limit_remaining == 4500
        assert client._rate_limit_reset is not None

    def test_update_rate_limit_missing_headers(self, client: GitHubClient) -> None:
        """Test rate limit update with missing headers."""
        response = MagicMock()
        response.headers = {}

        original_remaining = client._rate_limit_remaining
        client._update_rate_limit(response)
        assert client._rate_limit_remaining == original_remaining

    @pytest.mark.asyncio
    async def test_request_rate_limit_check(self, client: GitHubClient) -> None:
        """Test request checks rate limit buffer."""
        client._rate_limit_remaining = 5  # Below buffer
        client.config.github.rate_limit_buffer = 10

        with pytest.raises(RateLimitExceeded):
            await client._request("GET", "/test")

    @pytest.mark.asyncio
    async def test_request_success(self, client: GitHubClient) -> None:
        """Test successful request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.json.return_value = {"data": "test"}

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http_client

            result = await client._request("GET", "/test")
            assert result == {"data": "test"}

    @pytest.mark.asyncio
    async def test_request_403_rate_limit(self, client: GitHubClient) -> None:
        """Test 403 response with rate limit message."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {}
        mock_response.text = "API rate limit exceeded"

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http_client

            with pytest.raises(RateLimitExceeded):
                await client._request("GET", "/test")

    @pytest.mark.asyncio
    async def test_request_403_forbidden(self, client: GitHubClient) -> None:
        """Test 403 response without rate limit."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {}
        mock_response.text = "Access denied"

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http_client

            with pytest.raises(GitHubAPIError) as exc_info:
                await client._request("GET", "/test")
            assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_request_404(self, client: GitHubClient) -> None:
        """Test 404 response."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.headers = {}
        mock_response.text = "Not found"

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http_client

            with pytest.raises(GitHubAPIError) as exc_info:
                await client._request("GET", "/test")
            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_request_500(self, client: GitHubClient) -> None:
        """Test 500 response."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.headers = {}
        mock_response.text = "Internal server error"

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http_client = AsyncMock()
            mock_http_client.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http_client

            with pytest.raises(GitHubAPIError) as exc_info:
                await client._request("GET", "/test")
            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_get_repositories(self, client: GitHubClient) -> None:
        """Test getting repositories."""
        repos = [{"name": "repo1"}, {"name": "repo2"}]

        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = repos

            result = await client.get_repositories()
            assert result == repos

    @pytest.mark.asyncio
    async def test_get_repositories_pagination(self, client: GitHubClient) -> None:
        """Test repository pagination."""
        page1 = [{"name": f"repo{i}"} for i in range(100)]
        page2 = [{"name": f"repo{i}"} for i in range(100, 150)]

        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = [page1, page2]

            result = await client.get_repositories()
            assert len(result) == 150

    @pytest.mark.asyncio
    async def test_get_repositories_empty(self, client: GitHubClient) -> None:
        """Test getting empty repositories list."""
        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = []

            result = await client.get_repositories()
            assert result == []

    @pytest.mark.asyncio
    async def test_get_repository(self, client: GitHubClient) -> None:
        """Test getting single repository."""
        repo = {"name": "test-repo", "full_name": "org/test-repo"}

        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = repo

            result = await client.get_repository("test-repo")
            assert result == repo

    @pytest.mark.asyncio
    async def test_get_latest_commit(self, client: GitHubClient) -> None:
        """Test getting latest commit."""
        commit = {"sha": "abc123", "commit": {"message": "Test commit"}}

        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = commit

            result = await client.get_latest_commit("test-repo")
            assert result == commit

    @pytest.mark.asyncio
    async def test_get_latest_commit_not_found(self, client: GitHubClient) -> None:
        """Test getting latest commit when not found."""
        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = GitHubAPIError("Not found", 404)

            result = await client.get_latest_commit("test-repo")
            assert result is None

    @pytest.mark.asyncio
    async def test_get_workflow_runs(self, client: GitHubClient) -> None:
        """Test getting workflow runs."""
        runs = {"workflow_runs": [{"id": 1}, {"id": 2}]}

        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = runs

            result = await client.get_workflow_runs("test-repo")
            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_workflow_runs_error(self, client: GitHubClient) -> None:
        """Test getting workflow runs with error."""
        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = GitHubAPIError("Error", 500)

            result = await client.get_workflow_runs("test-repo")
            assert result == []

    @pytest.mark.asyncio
    async def test_get_vulnerability_alerts(self, client: GitHubClient) -> None:
        """Test getting vulnerability alerts."""
        alerts = [{"number": 1, "state": "open"}]

        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = alerts

            result = await client.get_vulnerability_alerts("test-repo")
            assert result == alerts

    @pytest.mark.asyncio
    async def test_get_vulnerability_alerts_error(self, client: GitHubClient) -> None:
        """Test getting vulnerability alerts with error."""
        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = GitHubAPIError("Error", 500)

            result = await client.get_vulnerability_alerts("test-repo")
            assert result == []

    @pytest.mark.asyncio
    async def test_get_releases(self, client: GitHubClient) -> None:
        """Test getting releases."""
        releases = [{"tag_name": "v1.0.0"}]

        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = releases

            result = await client.get_releases("test-repo")
            assert result == releases

    @pytest.mark.asyncio
    async def test_get_releases_error(self, client: GitHubClient) -> None:
        """Test getting releases with error."""
        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = GitHubAPIError("Error", 500)

            result = await client.get_releases("test-repo")
            assert result == []

    @pytest.mark.asyncio
    async def test_get_contents(self, client: GitHubClient) -> None:
        """Test getting contents."""
        contents = {"name": "README.md", "type": "file"}

        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = contents

            result = await client.get_contents("test-repo", "README.md")
            assert result == contents

    @pytest.mark.asyncio
    async def test_get_contents_not_found(self, client: GitHubClient) -> None:
        """Test getting contents when not found."""
        with patch.object(client, "_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = GitHubAPIError("Not found", 404)

            result = await client.get_contents("test-repo", "nonexistent.md")
            assert result is None


class TestGitHubClientHelpers:
    """Tests for GitHubClient helper methods."""

    @pytest.fixture
    def client(self) -> GitHubClient:
        """Create GitHub client."""
        return GitHubClient(PulseConfig())

    def test_parse_datetime_valid(self, client: GitHubClient) -> None:
        """Test parsing valid datetime."""
        result = client._parse_datetime("2024-01-15T10:30:00Z")
        assert result is not None
        assert result.year == 2024

    def test_parse_datetime_none(self, client: GitHubClient) -> None:
        """Test parsing None datetime."""
        result = client._parse_datetime(None)
        assert result is None

    def test_parse_datetime_invalid(self, client: GitHubClient) -> None:
        """Test parsing invalid datetime."""
        result = client._parse_datetime("invalid")
        assert result is None

    def test_map_language_rust(self, client: GitHubClient) -> None:
        """Test mapping Rust language."""
        assert client._map_language("Rust") == Language.RUST
        assert client._map_language("rust") == Language.RUST

    def test_map_language_python(self, client: GitHubClient) -> None:
        """Test mapping Python language."""
        assert client._map_language("Python") == Language.PYTHON

    def test_map_language_javascript(self, client: GitHubClient) -> None:
        """Test mapping JavaScript language."""
        assert client._map_language("JavaScript") == Language.JAVASCRIPT

    def test_map_language_typescript(self, client: GitHubClient) -> None:
        """Test mapping TypeScript language."""
        assert client._map_language("TypeScript") == Language.TYPESCRIPT

    def test_map_language_html(self, client: GitHubClient) -> None:
        """Test mapping HTML language."""
        assert client._map_language("HTML") == Language.HTML

    def test_map_language_shell(self, client: GitHubClient) -> None:
        """Test mapping Shell language."""
        assert client._map_language("Shell") == Language.SHELL

    def test_map_language_other(self, client: GitHubClient) -> None:
        """Test mapping unknown language."""
        assert client._map_language("Go") == Language.OTHER
        assert client._map_language("Java") == Language.OTHER

    def test_map_language_none(self, client: GitHubClient) -> None:
        """Test mapping None language."""
        assert client._map_language(None) == Language.OTHER

    def test_map_severity_critical(self, client: GitHubClient) -> None:
        """Test mapping critical severity."""
        assert client._map_severity("critical") == Severity.CRITICAL
        assert client._map_severity("CRITICAL") == Severity.CRITICAL

    def test_map_severity_high(self, client: GitHubClient) -> None:
        """Test mapping high severity."""
        assert client._map_severity("high") == Severity.HIGH

    def test_map_severity_medium(self, client: GitHubClient) -> None:
        """Test mapping medium severity."""
        assert client._map_severity("medium") == Severity.MEDIUM
        assert client._map_severity("moderate") == Severity.MEDIUM

    def test_map_severity_low(self, client: GitHubClient) -> None:
        """Test mapping low severity."""
        assert client._map_severity("low") == Severity.LOW

    def test_map_severity_info(self, client: GitHubClient) -> None:
        """Test mapping info severity."""
        assert client._map_severity("info") == Severity.INFO

    def test_map_severity_unknown(self, client: GitHubClient) -> None:
        """Test mapping unknown severity."""
        assert client._map_severity("unknown") == Severity.INFO

    def test_map_build_status_passing(self, client: GitHubClient) -> None:
        """Test mapping passing build status."""
        assert client._map_build_status("completed", "success") == BuildStatus.PASSING

    def test_map_build_status_failing(self, client: GitHubClient) -> None:
        """Test mapping failing build status."""
        assert client._map_build_status("completed", "failure") == BuildStatus.FAILING
        assert client._map_build_status("completed", "cancelled") == BuildStatus.FAILING

    def test_map_build_status_pending(self, client: GitHubClient) -> None:
        """Test mapping pending build status."""
        assert client._map_build_status("queued", None) == BuildStatus.PENDING
        assert client._map_build_status("in_progress", None) == BuildStatus.PENDING

    def test_map_build_status_unknown(self, client: GitHubClient) -> None:
        """Test mapping unknown build status."""
        assert client._map_build_status(None, None) == BuildStatus.UNKNOWN
        assert client._map_build_status("other", None) == BuildStatus.UNKNOWN

    def test_rate_limit_properties(self, client: GitHubClient) -> None:
        """Test rate limit property accessors."""
        assert client.rate_limit_remaining == 5000
        assert client.rate_limit_reset is None

        client._rate_limit_remaining = 100
        client._rate_limit_reset = datetime.now()

        assert client.rate_limit_remaining == 100
        assert client.rate_limit_reset is not None


class TestBuildRepoHealth:
    """Tests for build_repo_health method."""

    @pytest.fixture
    def client(self) -> GitHubClient:
        """Create GitHub client."""
        return GitHubClient(PulseConfig())

    @pytest.fixture
    def repo_data(self) -> dict:
        """Create sample repo data."""
        return {
            "name": "test-repo",
            "full_name": "test-org/test-repo",
            "html_url": "https://github.com/test-org/test-repo",
            "description": "Test repository",
            "language": "Python",
            "default_branch": "main",
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "stargazers_count": 100,
            "forks_count": 20,
            "open_issues_count": 5,
            "watchers_count": 50,
            "size": 1024,
        }

    @pytest.mark.asyncio
    async def test_build_repo_health_basic(
        self, client: GitHubClient, repo_data: dict
    ) -> None:
        """Test building basic repo health."""
        with patch.multiple(
            client,
            get_latest_commit=AsyncMock(return_value=None),
            get_workflow_runs=AsyncMock(return_value=[]),
            get_vulnerability_alerts=AsyncMock(return_value=[]),
            get_releases=AsyncMock(return_value=[]),
            get_contents=AsyncMock(return_value=None),
        ):
            health = await client.build_repo_health(repo_data)

            assert health.name == "test-repo"
            assert health.full_name == "test-org/test-repo"
            assert health.language == Language.PYTHON
            assert health.metrics.stars == 100
            assert health.metrics.forks == 20

    @pytest.mark.asyncio
    async def test_build_repo_health_with_commit(
        self, client: GitHubClient, repo_data: dict
    ) -> None:
        """Test building repo health with commit data."""
        commit_data = {
            "sha": "abc123",
            "commit": {
                "author": {
                    "date": "2024-01-15T10:30:00Z",
                }
            }
        }

        with patch.multiple(
            client,
            get_latest_commit=AsyncMock(return_value=commit_data),
            get_workflow_runs=AsyncMock(return_value=[]),
            get_vulnerability_alerts=AsyncMock(return_value=[]),
            get_releases=AsyncMock(return_value=[]),
            get_contents=AsyncMock(return_value=None),
        ):
            health = await client.build_repo_health(repo_data)
            assert health.last_commit is not None

    @pytest.mark.asyncio
    async def test_build_repo_health_with_workflows(
        self, client: GitHubClient, repo_data: dict
    ) -> None:
        """Test building repo health with workflow data."""
        workflow_runs = [
            {
                "name": "CI",
                "status": "completed",
                "conclusion": "success",
                "html_url": "https://github.com/test-org/test-repo/actions/runs/1",
                "run_started_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:30:00Z",
            }
        ]

        with patch.multiple(
            client,
            get_latest_commit=AsyncMock(return_value=None),
            get_workflow_runs=AsyncMock(return_value=workflow_runs),
            get_vulnerability_alerts=AsyncMock(return_value=[]),
            get_releases=AsyncMock(return_value=[]),
            get_contents=AsyncMock(return_value=None),
        ):
            health = await client.build_repo_health(repo_data)
            assert len(health.ci_status) == 1
            assert health.latest_build == BuildStatus.PASSING

    @pytest.mark.asyncio
    async def test_build_repo_health_with_vulnerabilities(
        self, client: GitHubClient, repo_data: dict
    ) -> None:
        """Test building repo health with vulnerability data."""
        alerts = [
            {
                "number": 1,
                "dependency": {"package": {"name": "requests"}},
                "security_advisory": {
                    "severity": "high",
                    "summary": "Security issue",
                    "description": "Details",
                    "cve_id": "CVE-2024-0001",
                    "references": [{"url": "https://example.com"}],
                },
                "security_vulnerability": {
                    "first_patched_version": {"identifier": "2.32.0"}
                },
                "created_at": "2024-01-01T00:00:00Z",
            }
        ]

        with patch.multiple(
            client,
            get_latest_commit=AsyncMock(return_value=None),
            get_workflow_runs=AsyncMock(return_value=[]),
            get_vulnerability_alerts=AsyncMock(return_value=alerts),
            get_releases=AsyncMock(return_value=[]),
            get_contents=AsyncMock(return_value=None),
        ):
            health = await client.build_repo_health(repo_data)
            assert health.vulnerability_report is not None
            assert health.vulnerability_report.total_alerts == 1
            assert health.vulnerability_report.high_count == 1

    @pytest.mark.asyncio
    async def test_build_repo_health_with_releases(
        self, client: GitHubClient, repo_data: dict
    ) -> None:
        """Test building repo health with release data."""
        releases = [{"tag_name": "v1.0.0", "published_at": "2024-01-01T00:00:00Z"}]

        with patch.multiple(
            client,
            get_latest_commit=AsyncMock(return_value=None),
            get_workflow_runs=AsyncMock(return_value=[]),
            get_vulnerability_alerts=AsyncMock(return_value=[]),
            get_releases=AsyncMock(return_value=releases),
            get_contents=AsyncMock(return_value=None),
        ):
            health = await client.build_repo_health(repo_data)
            assert health.last_release is not None

    @pytest.mark.asyncio
    async def test_build_repo_health_with_files(
        self, client: GitHubClient, repo_data: dict
    ) -> None:
        """Test building repo health with file presence."""
        readme = {"name": "README.md", "type": "file"}
        license_file = {"name": "LICENSE", "type": "file"}
        workflows = {"name": ".github/workflows", "type": "dir"}

        with patch.multiple(
            client,
            get_latest_commit=AsyncMock(return_value=None),
            get_workflow_runs=AsyncMock(return_value=[]),
            get_vulnerability_alerts=AsyncMock(return_value=[]),
            get_releases=AsyncMock(return_value=[]),
        ):
            with patch.object(
                client, "get_contents", new_callable=AsyncMock
            ) as mock_contents:
                mock_contents.side_effect = [
                    None,  # commit data
                    [],  # workflow runs
                    [],  # alerts
                    [],  # releases
                    readme,  # README.md
                    license_file,  # LICENSE
                    workflows,  # .github/workflows
                ]

                # Use a simpler approach - mock the specific calls
                async def mock_get_contents(repo: str, path: str) -> dict | None:
                    if "README" in path:
                        return readme
                    if "LICENSE" in path:
                        return license_file
                    if "workflows" in path:
                        return workflows
                    return None

                with patch.object(client, "get_contents", side_effect=mock_get_contents):
                    health = await client.build_repo_health(repo_data)
                    assert health.has_readme is True
                    assert health.has_license is True
                    assert health.has_ci is True

    @pytest.mark.asyncio
    async def test_build_repo_health_score_healthy(
        self, client: GitHubClient, repo_data: dict
    ) -> None:
        """Test building repo health results in healthy status."""
        with patch.multiple(
            client,
            get_latest_commit=AsyncMock(return_value={
                "commit": {"author": {"date": datetime.now().isoformat()}}
            }),
            get_workflow_runs=AsyncMock(return_value=[
                {"name": "CI", "status": "completed", "conclusion": "success"}
            ]),
            get_vulnerability_alerts=AsyncMock(return_value=[]),
            get_releases=AsyncMock(return_value=[]),
            get_contents=AsyncMock(return_value={"type": "file"}),
        ):
            health = await client.build_repo_health(repo_data)
            assert health.score >= 80
            assert health.status.value == "healthy"

    @pytest.mark.asyncio
    async def test_build_repo_health_handles_exceptions(
        self, client: GitHubClient, repo_data: dict
    ) -> None:
        """Test building repo health handles exceptions gracefully."""
        with patch.multiple(
            client,
            get_latest_commit=AsyncMock(side_effect=Exception("Network error")),
            get_workflow_runs=AsyncMock(side_effect=Exception("Network error")),
            get_vulnerability_alerts=AsyncMock(side_effect=Exception("Network error")),
            get_releases=AsyncMock(side_effect=Exception("Network error")),
            get_contents=AsyncMock(side_effect=Exception("Network error")),
        ):
            # Should not raise
            health = await client.build_repo_health(repo_data)
            assert health.name == "test-repo"
