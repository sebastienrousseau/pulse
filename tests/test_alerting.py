"""Tests for alerting module."""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from pulse.alerting import (
    AlertEvent,
    AlertManager,
    ConsoleChannel,
    SlackChannel,
    WebhookChannel,
)
from pulse.config import AlertConfig
from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    RepoHealth,
    VulnerabilityReport,
)


class TestAlertEvent:
    """Tests for AlertEvent."""

    def test_create_event(self) -> None:
        """Test creating an alert event."""
        event = AlertEvent(
            event_type=AlertEvent.CRITICAL_HEALTH,
            title="Test Alert",
            message="This is a test",
            severity="warning",
        )

        assert event.event_type == AlertEvent.CRITICAL_HEALTH
        assert event.title == "Test Alert"
        assert event.message == "This is a test"
        assert event.severity == "warning"
        assert event.repo is None
        assert isinstance(event.timestamp, datetime)

    def test_event_with_repo(self) -> None:
        """Test event with repository reference."""
        repo = RepoHealth(
            name="test-repo",
            full_name="org/test-repo",
            url="https://github.com/org/test-repo",
            status=HealthStatus.CRITICAL,
        )

        event = AlertEvent(
            event_type=AlertEvent.BUILD_FAILURE,
            title="Build Failed",
            message="Build failed",
            severity="critical",
            repo=repo,
        )

        assert event.repo is not None
        assert event.repo.name == "test-repo"

    def test_to_dict(self) -> None:
        """Test serialization."""
        event = AlertEvent(
            event_type=AlertEvent.VULNERABILITY,
            title="Security Alert",
            message="Found vulnerabilities",
            severity="critical",
            metadata={"count": 5},
        )

        data = event.to_dict()

        assert data["event_type"] == AlertEvent.VULNERABILITY
        assert data["title"] == "Security Alert"
        assert data["severity"] == "critical"
        assert data["metadata"]["count"] == 5
        assert "timestamp" in data


class TestConsoleChannel:
    """Tests for ConsoleChannel."""

    @pytest.mark.asyncio
    async def test_send(self, capsys) -> None:
        """Test sending to console."""
        channel = ConsoleChannel(color=False)
        event = AlertEvent(
            event_type=AlertEvent.SCAN_COMPLETE,
            title="Scan Done",
            message="All repos scanned",
            severity="info",
        )

        result = await channel.send(event)

        assert result is True
        captured = capsys.readouterr()
        assert "Scan Done" in captured.out
        assert "All repos scanned" in captured.out

    def test_is_configured(self) -> None:
        """Test channel is always configured."""
        channel = ConsoleChannel()
        assert channel.is_configured() is True

    def test_name(self) -> None:
        """Test channel name."""
        channel = ConsoleChannel()
        assert channel.name == "console"


class TestSlackChannel:
    """Tests for SlackChannel."""

    def test_not_configured(self) -> None:
        """Test unconfigured channel."""
        channel = SlackChannel()
        assert channel.is_configured() is False

    def test_configured(self) -> None:
        """Test configured channel."""
        channel = SlackChannel(webhook_url="https://hooks.slack.com/xxx")
        assert channel.is_configured() is True

    @pytest.mark.asyncio
    async def test_send_unconfigured(self) -> None:
        """Test send returns False when unconfigured."""
        channel = SlackChannel()
        event = AlertEvent(
            event_type=AlertEvent.CRITICAL_HEALTH,
            title="Test",
            message="Test",
            severity="critical",
        )

        result = await channel.send(event)
        assert result is False

    @pytest.mark.asyncio
    async def test_send_success(self) -> None:
        """Test successful send."""
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")

        with patch("httpx.AsyncClient.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            event = AlertEvent(
                event_type=AlertEvent.BUILD_FAILURE,
                title="Build Failed",
                message="Pipeline failed",
                severity="warning",
            )

            result = await channel.send(event)
            assert result is True


class TestWebhookChannel:
    """Tests for WebhookChannel."""

    def test_not_configured(self) -> None:
        """Test unconfigured channel."""
        channel = WebhookChannel()
        assert channel.is_configured() is False

    def test_configured(self) -> None:
        """Test configured channel."""
        channel = WebhookChannel(url="https://example.com/webhook")
        assert channel.is_configured() is True

    @pytest.mark.asyncio
    async def test_send_success(self) -> None:
        """Test successful webhook send."""
        channel = WebhookChannel(
            url="https://example.com/webhook",
            headers={"X-Custom": "value"},
        )

        with patch("httpx.AsyncClient.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            event = AlertEvent(
                event_type=AlertEvent.SCAN_COMPLETE,
                title="Scan Complete",
                message="Done",
                severity="info",
            )

            result = await channel.send(event)
            assert result is True


class TestAlertManager:
    """Tests for AlertManager."""

    @pytest.fixture
    def config(self) -> AlertConfig:
        """Create alert config."""
        return AlertConfig(
            enabled=True,
            alert_on_critical=True,
            alert_on_build_failure=True,
            alert_on_vulnerability=True,
        )

    @pytest.fixture
    def manager(self, config: AlertConfig) -> AlertManager:
        """Create alert manager."""
        return AlertManager(config)

    def test_enabled(self, manager: AlertManager) -> None:
        """Test enabled state."""
        assert manager.enabled is True

    def test_add_channel(self, manager: AlertManager) -> None:
        """Test adding a channel."""
        channel = ConsoleChannel()
        manager.add_channel(channel)

        assert len(manager.channels) == 1
        assert manager.channels[0].name == "console"

    def test_remove_channel(self, manager: AlertManager) -> None:
        """Test removing a channel."""
        channel = ConsoleChannel()
        manager.add_channel(channel)

        removed = manager.remove_channel("console")
        assert removed is True
        assert len(manager.channels) == 0

        removed = manager.remove_channel("nonexistent")
        assert removed is False

    @pytest.mark.asyncio
    async def test_send_to_all_channels(self, manager: AlertManager) -> None:
        """Test sending to all channels."""
        channel1 = ConsoleChannel(color=False)
        channel2 = ConsoleChannel(color=False)
        manager.add_channel(channel1)
        manager.add_channel(channel2)

        event = AlertEvent(
            event_type=AlertEvent.CRITICAL_HEALTH,
            title="Test",
            message="Test message",
            severity="critical",
        )

        results = await manager.send(event)

        assert "console" in results
        assert results["console"] is True

    @pytest.mark.asyncio
    async def test_alert_critical(self, manager: AlertManager) -> None:
        """Test critical alert."""
        channel = ConsoleChannel(color=False)
        manager.add_channel(channel)

        repo = RepoHealth(
            name="failing-repo",
            full_name="org/failing-repo",
            url="https://github.com/org/failing-repo",
            status=HealthStatus.CRITICAL,
            score=25.0,
        )

        results = await manager.alert_critical(repo)
        assert "console" in results

    @pytest.mark.asyncio
    async def test_alert_build_failure(self, manager: AlertManager) -> None:
        """Test build failure alert."""
        from pulse.models import CIStatus

        channel = ConsoleChannel(color=False)
        manager.add_channel(channel)

        repo = RepoHealth(
            name="failing-repo",
            full_name="org/failing-repo",
            url="https://github.com/org/failing-repo",
            latest_build=BuildStatus.FAILING,
            ci_status=[
                CIStatus(
                    workflow_name="CI",
                    status=BuildStatus.FAILING,
                )
            ],
        )

        results = await manager.alert_build_failure(repo)
        assert "console" in results

    @pytest.mark.asyncio
    async def test_alert_vulnerability(self, manager: AlertManager) -> None:
        """Test vulnerability alert."""
        channel = ConsoleChannel(color=False)
        manager.add_channel(channel)

        repo = RepoHealth(
            name="vulnerable-repo",
            full_name="org/vulnerable-repo",
            url="https://github.com/org/vulnerable-repo",
            vulnerability_report=VulnerabilityReport(
                repo_name="vulnerable-repo",
                total_alerts=5,
                critical_count=2,
                high_count=3,
            ),
        )

        results = await manager.alert_vulnerability(repo)
        assert "console" in results

    @pytest.mark.asyncio
    async def test_disabled_manager(self) -> None:
        """Test disabled manager sends nothing."""
        config = AlertConfig(enabled=False)
        manager = AlertManager(config)
        channel = ConsoleChannel()
        manager.add_channel(channel)

        event = AlertEvent(
            event_type=AlertEvent.CRITICAL_HEALTH,
            title="Test",
            message="Test",
            severity="critical",
        )

        results = await manager.send(event)
        assert results == {}

    @pytest.mark.asyncio
    async def test_event_history(self, manager: AlertManager) -> None:
        """Test event history is maintained."""
        channel = ConsoleChannel(color=False)
        manager.add_channel(channel)

        for i in range(3):
            event = AlertEvent(
                event_type=AlertEvent.SCAN_COMPLETE,
                title=f"Scan {i}",
                message="Done",
                severity="info",
            )
            await manager.send(event)

        history = manager.event_history
        assert len(history) == 3
        assert history[0].title == "Scan 0"
        assert history[2].title == "Scan 2"

    @pytest.mark.asyncio
    async def test_alert_scan_complete(self, manager: AlertManager) -> None:
        """Test scan complete alert."""
        channel = ConsoleChannel(color=False)
        manager.add_channel(channel)

        summary = EcosystemSummary(organization="test-org")
        summary.total_repos = 10
        summary.healthy_count = 7
        summary.warning_count = 2
        summary.critical_count = 1

        results = await manager.alert_scan_complete(summary)
        assert "console" in results
