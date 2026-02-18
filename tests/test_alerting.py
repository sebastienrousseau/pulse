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

    @pytest.mark.asyncio
    async def test_alert_critical_disabled(self) -> None:
        """Test critical alert when disabled."""
        config = AlertConfig(enabled=True, alert_on_critical=False)
        manager = AlertManager(config)
        channel = ConsoleChannel()
        manager.add_channel(channel)

        repo = RepoHealth(
            name="repo",
            full_name="org/repo",
            url="https://github.com/org/repo",
            status=HealthStatus.CRITICAL,
        )

        results = await manager.alert_critical(repo)
        assert results == {}

    @pytest.mark.asyncio
    async def test_alert_build_failure_disabled(self) -> None:
        """Test build failure alert when disabled."""
        config = AlertConfig(enabled=True, alert_on_build_failure=False)
        manager = AlertManager(config)
        channel = ConsoleChannel()
        manager.add_channel(channel)

        repo = RepoHealth(
            name="repo",
            full_name="org/repo",
            url="https://github.com/org/repo",
            latest_build=BuildStatus.FAILING,
        )

        results = await manager.alert_build_failure(repo)
        assert results == {}

    @pytest.mark.asyncio
    async def test_alert_vulnerability_disabled(self) -> None:
        """Test vulnerability alert when disabled."""
        config = AlertConfig(enabled=True, alert_on_vulnerability=False)
        manager = AlertManager(config)
        channel = ConsoleChannel()
        manager.add_channel(channel)

        repo = RepoHealth(
            name="repo",
            full_name="org/repo",
            url="https://github.com/org/repo",
            vulnerability_report=VulnerabilityReport(
                repo_name="repo",
                total_alerts=5,
            ),
        )

        results = await manager.alert_vulnerability(repo)
        assert results == {}

    @pytest.mark.asyncio
    async def test_alert_vulnerability_no_report(self, manager: AlertManager) -> None:
        """Test vulnerability alert with no vulnerability report."""
        channel = ConsoleChannel()
        manager.add_channel(channel)

        repo = RepoHealth(
            name="repo",
            full_name="org/repo",
            url="https://github.com/org/repo",
            vulnerability_report=None,
        )

        results = await manager.alert_vulnerability(repo)
        assert results == {}

    @pytest.mark.asyncio
    async def test_alert_vulnerability_with_min_severity(self, manager: AlertManager) -> None:
        """Test vulnerability alert with minimum severity filter."""
        from pulse.models import Severity

        channel = ConsoleChannel(color=False)
        manager.add_channel(channel)

        # Repo with only low severity - should not alert when min is HIGH
        repo = RepoHealth(
            name="repo",
            full_name="org/repo",
            url="https://github.com/org/repo",
            vulnerability_report=VulnerabilityReport(
                repo_name="repo",
                total_alerts=3,
                low_count=3,
            ),
        )

        results = await manager.alert_vulnerability(repo, min_severity=Severity.HIGH)
        assert results == {}

        # Repo with high severity - should alert
        repo2 = RepoHealth(
            name="repo2",
            full_name="org/repo2",
            url="https://github.com/org/repo2",
            vulnerability_report=VulnerabilityReport(
                repo_name="repo2",
                total_alerts=3,
                high_count=2,
                low_count=1,
            ),
        )

        results2 = await manager.alert_vulnerability(repo2, min_severity=Severity.HIGH)
        assert "console" in results2

    @pytest.mark.asyncio
    async def test_process_summary(self, manager: AlertManager) -> None:
        """Test processing full summary."""
        channel = ConsoleChannel(color=False)
        manager.add_channel(channel)

        summary = EcosystemSummary(organization="test-org")

        # Add critical repo
        critical = RepoHealth(
            name="critical-repo",
            full_name="org/critical-repo",
            url="https://github.com/org/critical-repo",
            status=HealthStatus.CRITICAL,
            latest_build=BuildStatus.FAILING,
            vulnerability_report=VulnerabilityReport(
                repo_name="critical-repo",
                total_alerts=5,
                critical_count=2,
            ),
        )
        summary.add_repo(critical)

        # Add healthy repo
        healthy = RepoHealth(
            name="healthy-repo",
            full_name="org/healthy-repo",
            url="https://github.com/org/healthy-repo",
            status=HealthStatus.HEALTHY,
        )
        summary.add_repo(healthy)

        events = await manager.process_summary(summary)
        # Should have: critical, build failure, vulnerability, scan complete
        assert len(events) >= 3  # At least critical, build, and scan complete

    @pytest.mark.asyncio
    async def test_channel_exception_handling(self, manager: AlertManager) -> None:
        """Test that channel exceptions are handled gracefully."""
        from pulse.alerting import AlertChannel

        class FailingChannel(AlertChannel):
            @property
            def name(self) -> str:
                return "failing"

            def is_configured(self) -> bool:
                return True

            async def send(self, event: AlertEvent) -> bool:
                raise RuntimeError("Channel failed")

        manager.add_channel(FailingChannel())

        event = AlertEvent(
            event_type=AlertEvent.SCAN_COMPLETE,
            title="Test",
            message="Test",
            severity="info",
        )

        results = await manager.send(event)
        assert results["failing"] is False

    def test_manager_auto_configure_slack(self) -> None:
        """Test manager auto-configures Slack from config."""
        config = AlertConfig(
            enabled=True,
            slack_webhook="https://hooks.slack.com/test",
        )
        manager = AlertManager(config)

        assert len(manager.channels) == 1
        assert manager.channels[0].name == "slack"

    def test_add_unconfigured_channel(self, manager: AlertManager) -> None:
        """Test that unconfigured channels are not added."""
        channel = SlackChannel()  # No webhook URL
        manager.add_channel(channel)

        assert len(manager.channels) == 0


class TestSlackChannelAdvanced:
    """Advanced tests for SlackChannel."""

    @pytest.mark.asyncio
    async def test_send_with_repo(self) -> None:
        """Test Slack send with repo info."""
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")

        repo = RepoHealth(
            name="test-repo",
            full_name="org/test-repo",
            url="https://github.com/org/test-repo",
            status=HealthStatus.WARNING,
        )

        with patch("httpx.AsyncClient.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            event = AlertEvent(
                event_type=AlertEvent.BUILD_FAILURE,
                title="Build Failed",
                message="Pipeline failed",
                severity="warning",
                repo=repo,
            )

            result = await channel.send(event)
            assert result is True

    @pytest.mark.asyncio
    async def test_send_request_error(self) -> None:
        """Test Slack send with request error."""
        import httpx

        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")

        with patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("Network error")):
            event = AlertEvent(
                event_type=AlertEvent.CRITICAL_HEALTH,
                title="Test",
                message="Test",
                severity="critical",
            )

            result = await channel.send(event)
            assert result is False

    def test_slack_name_property(self) -> None:
        """Test Slack channel name."""
        channel = SlackChannel()
        assert channel.name == "slack"


class TestWebhookChannelAdvanced:
    """Advanced tests for WebhookChannel."""

    @pytest.mark.asyncio
    async def test_send_unconfigured(self) -> None:
        """Test webhook send when unconfigured."""
        channel = WebhookChannel()

        event = AlertEvent(
            event_type=AlertEvent.SCAN_COMPLETE,
            title="Test",
            message="Test",
            severity="info",
        )

        result = await channel.send(event)
        assert result is False

    @pytest.mark.asyncio
    async def test_send_request_error(self) -> None:
        """Test webhook send with request error."""
        import httpx

        channel = WebhookChannel(url="https://example.com/webhook")

        with patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("Network error")):
            event = AlertEvent(
                event_type=AlertEvent.CRITICAL_HEALTH,
                title="Test",
                message="Test",
                severity="critical",
            )

            result = await channel.send(event)
            assert result is False

    def test_webhook_name_property(self) -> None:
        """Test webhook channel name."""
        channel = WebhookChannel()
        assert channel.name == "webhook"


class TestEmailChannel:
    """Tests for EmailChannel."""

    def test_not_configured(self) -> None:
        """Test unconfigured email channel."""
        from pulse.alerting import EmailChannel

        channel = EmailChannel()
        assert channel.is_configured() is False

    def test_configured(self) -> None:
        """Test configured email channel."""
        from pulse.alerting import EmailChannel

        channel = EmailChannel(recipients=["test@example.com"])
        assert channel.is_configured() is True

    def test_name_property(self) -> None:
        """Test email channel name."""
        from pulse.alerting import EmailChannel

        channel = EmailChannel()
        assert channel.name == "email"

    @pytest.mark.asyncio
    async def test_send_unconfigured(self) -> None:
        """Test send returns False when unconfigured."""
        from pulse.alerting import EmailChannel

        channel = EmailChannel()

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
        """Test successful email send."""
        from pulse.alerting import EmailChannel
        from unittest.mock import MagicMock, patch

        channel = EmailChannel(
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="user",
            password="pass",
            from_email="pulse@example.com",
            recipients=["admin@example.com"],
            use_tls=True,
        )

        event = AlertEvent(
            event_type=AlertEvent.CRITICAL_HEALTH,
            title="Critical Alert",
            message="Something is wrong",
            severity="critical",
        )

        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=None)

            result = await channel.send(event)
            assert result is True

    @pytest.mark.asyncio
    async def test_send_with_repo(self) -> None:
        """Test email send with repo info."""
        from pulse.alerting import EmailChannel
        from unittest.mock import MagicMock, patch

        channel = EmailChannel(
            recipients=["admin@example.com"],
            use_tls=False,
        )

        repo = RepoHealth(
            name="test-repo",
            full_name="org/test-repo",
            url="https://github.com/org/test-repo",
            status=HealthStatus.CRITICAL,
        )

        event = AlertEvent(
            event_type=AlertEvent.BUILD_FAILURE,
            title="Build Failed",
            message="Pipeline failed",
            severity="warning",
            repo=repo,
        )

        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=None)

            result = await channel.send(event)
            assert result is True

    @pytest.mark.asyncio
    async def test_send_smtp_error(self) -> None:
        """Test email send with SMTP error."""
        import smtplib
        from pulse.alerting import EmailChannel
        from unittest.mock import patch

        channel = EmailChannel(recipients=["admin@example.com"])

        event = AlertEvent(
            event_type=AlertEvent.SCAN_COMPLETE,
            title="Scan Complete",
            message="Done",
            severity="info",
        )

        with patch("smtplib.SMTP", side_effect=smtplib.SMTPException("Connection failed")):
            result = await channel.send(event)
            assert result is False

    @pytest.mark.asyncio
    async def test_send_os_error(self) -> None:
        """Test email send with OS error."""
        from pulse.alerting import EmailChannel
        from unittest.mock import patch

        channel = EmailChannel(recipients=["admin@example.com"])

        event = AlertEvent(
            event_type=AlertEvent.SCAN_COMPLETE,
            title="Scan Complete",
            message="Done",
            severity="info",
        )

        with patch("smtplib.SMTP", side_effect=OSError("Network unreachable")):
            result = await channel.send(event)
            assert result is False

    @pytest.mark.asyncio
    async def test_send_without_auth(self) -> None:
        """Test email send without authentication."""
        from pulse.alerting import EmailChannel
        from unittest.mock import MagicMock, patch

        channel = EmailChannel(
            smtp_host="localhost",
            smtp_port=25,
            recipients=["admin@example.com"],
            use_tls=False,
        )

        event = AlertEvent(
            event_type=AlertEvent.HEALTH_IMPROVED,
            title="Health Improved",
            message="Things are better",
            severity="success",
        )

        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
            mock_smtp.return_value.__exit__ = MagicMock(return_value=None)

            result = await channel.send(event)
            assert result is True
            # login should not be called when username/password not set
            mock_server.login.assert_not_called()


class TestConsoleChannelAdvanced:
    """Advanced tests for ConsoleChannel."""

    @pytest.mark.asyncio
    async def test_send_with_repo(self, capsys) -> None:
        """Test console send with repo info."""
        channel = ConsoleChannel(color=False)

        repo = RepoHealth(
            name="test-repo",
            full_name="org/test-repo",
            url="https://github.com/org/test-repo",
            status=HealthStatus.WARNING,
        )

        event = AlertEvent(
            event_type=AlertEvent.BUILD_FAILURE,
            title="Build Failed",
            message="Pipeline failed",
            severity="warning",
            repo=repo,
        )

        result = await channel.send(event)
        assert result is True

        captured = capsys.readouterr()
        assert "test-repo" in captured.out

    @pytest.mark.asyncio
    async def test_send_with_colors(self, capsys) -> None:
        """Test console send with colors enabled."""
        channel = ConsoleChannel(color=True)

        event = AlertEvent(
            event_type=AlertEvent.CRITICAL_HEALTH,
            title="Critical Alert",
            message="Something is wrong",
            severity="critical",
        )

        result = await channel.send(event)
        assert result is True

        captured = capsys.readouterr()
        assert "Critical Alert" in captured.out

    @pytest.mark.asyncio
    async def test_send_success_severity(self, capsys) -> None:
        """Test console send with success severity."""
        channel = ConsoleChannel(color=False)

        event = AlertEvent(
            event_type=AlertEvent.HEALTH_IMPROVED,
            title="Health Improved",
            message="Things are better",
            severity="success",
        )

        result = await channel.send(event)
        assert result is True

        captured = capsys.readouterr()
        assert "[SUCCESS]" in captured.out
