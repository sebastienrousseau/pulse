"""Alerting and notification system for Pulse.

Provides multi-channel notifications for ecosystem health events,
including Slack, email, and webhook integrations.
"""

from __future__ import annotations

import smtplib
from abc import ABC, abstractmethod
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx

from pulse.config import AlertConfig
from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    RepoHealth,
    Severity,
)


class AlertError(Exception):
    """Alert operation error."""

    pass


class AlertEvent:
    """Represents an alert event."""

    CRITICAL_HEALTH = "critical_health"
    BUILD_FAILURE = "build_failure"
    VULNERABILITY = "vulnerability"
    HEALTH_DEGRADED = "health_degraded"
    HEALTH_IMPROVED = "health_improved"
    SCAN_COMPLETE = "scan_complete"

    def __init__(
        self,
        event_type: str,
        title: str,
        message: str,
        severity: str = "info",
        repo: RepoHealth | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Initialize alert event.

        Args:
            event_type: Type of event.
            title: Alert title.
            message: Alert message.
            severity: Severity level (critical, warning, info).
            repo: Related repository.
            metadata: Additional metadata.
        """
        self.event_type = event_type
        self.title = title
        self.message = message
        self.severity = severity
        self.repo = repo
        self.metadata = metadata or {}
        self.timestamp = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_type": self.event_type,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "repo": self.repo.name if self.repo else None,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


class AlertChannel(ABC):
    """Base class for alert channels."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Get channel name."""
        pass

    @abstractmethod
    async def send(self, event: AlertEvent) -> bool:
        """Send alert through this channel.

        Args:
            event: Alert event to send.

        Returns:
            True if sent successfully.
        """
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if channel is properly configured."""
        pass


class SlackChannel(AlertChannel):
    """Slack webhook notification channel."""

    SEVERITY_COLORS = {
        "critical": "#dc3545",  # Red
        "warning": "#ffc107",  # Yellow
        "info": "#17a2b8",  # Blue
        "success": "#28a745",  # Green
    }

    SEVERITY_EMOJI = {
        "critical": ":rotating_light:",
        "warning": ":warning:",
        "info": ":information_source:",
        "success": ":white_check_mark:",
    }

    def __init__(self, webhook_url: str | None = None) -> None:
        """Initialize Slack channel.

        Args:
            webhook_url: Slack webhook URL.
        """
        self.webhook_url = webhook_url

    @property
    def name(self) -> str:
        """Get channel name."""
        return "slack"

    def is_configured(self) -> bool:
        """Check if Slack is configured."""
        return bool(self.webhook_url)

    async def send(self, event: AlertEvent) -> bool:
        """Send alert to Slack.

        Args:
            event: Alert event to send.

        Returns:
            True if sent successfully.
        """
        if not self.is_configured():
            return False

        emoji = self.SEVERITY_EMOJI.get(event.severity, ":bell:")
        color = self.SEVERITY_COLORS.get(event.severity, "#808080")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} {event.title}",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": event.message,
                            },
                        },
                    ],
                }
            ]
        }

        # Add repo info if available
        if event.repo:
            payload["attachments"][0]["blocks"].append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Repository:* <{event.repo.url}|{event.repo.name}>",
                        }
                    ],
                }
            )

        # Add timestamp
        payload["attachments"][0]["blocks"].append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "plain_text",
                        "text": f"Pulse - {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                    }
                ],
            }
        )

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10.0,
                )
                return response.status_code == 200
        except httpx.RequestError:
            return False


class WebhookChannel(AlertChannel):
    """Generic webhook notification channel."""

    def __init__(
        self,
        url: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initialize webhook channel.

        Args:
            url: Webhook URL.
            headers: Custom headers.
        """
        self.url = url
        self.headers = headers or {}

    @property
    def name(self) -> str:
        """Get channel name."""
        return "webhook"

    def is_configured(self) -> bool:
        """Check if webhook is configured."""
        return bool(self.url)

    async def send(self, event: AlertEvent) -> bool:
        """Send alert to webhook.

        Args:
            event: Alert event to send.

        Returns:
            True if sent successfully.
        """
        if not self.is_configured():
            return False

        payload = event.to_dict()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.url,
                    json=payload,
                    headers=self.headers,
                    timeout=10.0,
                )
                return 200 <= response.status_code < 300
        except httpx.RequestError:
            return False


class EmailChannel(AlertChannel):
    """Email notification channel using SMTP."""

    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 587,
        username: str | None = None,
        password: str | None = None,
        from_email: str = "pulse@localhost",
        recipients: list[str] | None = None,
        use_tls: bool = True,
    ) -> None:
        """Initialize email channel.

        Args:
            smtp_host: SMTP server host.
            smtp_port: SMTP server port.
            username: SMTP username.
            password: SMTP password.
            from_email: From email address.
            recipients: List of recipient emails.
            use_tls: Whether to use TLS.
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.recipients = recipients or []
        self.use_tls = use_tls

    @property
    def name(self) -> str:
        """Get channel name."""
        return "email"

    def is_configured(self) -> bool:
        """Check if email is configured."""
        return bool(self.recipients)

    async def send(self, event: AlertEvent) -> bool:
        """Send alert via email.

        Args:
            event: Alert event to send.

        Returns:
            True if sent successfully.
        """
        if not self.is_configured():
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Pulse] {event.title}"
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.recipients)

            # Plain text version
            text = f"""
Pulse Alert: {event.title}

{event.message}

Severity: {event.severity}
Time: {event.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
"""
            if event.repo:
                text += f"\nRepository: {event.repo.name} ({event.repo.url})"

            # HTML version
            severity_colors = {
                "critical": "#dc3545",
                "warning": "#ffc107",
                "info": "#17a2b8",
            }
            color = severity_colors.get(event.severity, "#808080")

            html = f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="border-left: 4px solid {color}; padding-left: 16px;">
        <h2 style="color: {color}; margin-bottom: 8px;">{event.title}</h2>
        <p style="color: #333;">{event.message}</p>
        <p style="color: #666; font-size: 12px;">
            Severity: {event.severity.upper()}<br>
            Time: {event.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
        </p>
    </div>
"""
            if event.repo:
                html += f"""
    <p style="color: #666; margin-top: 16px;">
        Repository: <a href="{event.repo.url}">{event.repo.name}</a>
    </p>
"""
            html += """
    <hr style="margin-top: 24px; border: none; border-top: 1px solid #ddd;">
    <p style="color: #999; font-size: 11px;">Sent by Pulse Ecosystem Monitor</p>
</body>
</html>
"""

            msg.attach(MIMEText(text, "plain"))
            msg.attach(MIMEText(html, "html"))

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(
                    self.from_email,
                    self.recipients,
                    msg.as_string(),
                )

            return True

        except (smtplib.SMTPException, OSError):
            return False


class AlertManager:
    """Manages alert channels and event dispatching.

    Example:
        >>> manager = AlertManager(config.alerts)
        >>> manager.add_channel(SlackChannel(webhook_url))
        >>> await manager.alert_critical(repo)
    """

    def __init__(self, config: AlertConfig | None = None) -> None:
        """Initialize alert manager.

        Args:
            config: Alert configuration.
        """
        self.config = config or AlertConfig()
        self._channels: list[AlertChannel] = []
        self._event_history: list[AlertEvent] = []
        self._max_history = 100

        # Auto-configure channels from config
        if config and config.slack_webhook:
            self.add_channel(SlackChannel(config.slack_webhook))

    @property
    def enabled(self) -> bool:
        """Check if alerting is enabled."""
        return self.config.enabled

    @property
    def channels(self) -> list[AlertChannel]:
        """Get configured channels."""
        return self._channels

    @property
    def event_history(self) -> list[AlertEvent]:
        """Get recent event history."""
        return self._event_history[-self._max_history :]

    def add_channel(self, channel: AlertChannel) -> None:
        """Add notification channel.

        Args:
            channel: Channel to add.
        """
        if channel.is_configured():
            self._channels.append(channel)

    def remove_channel(self, channel_name: str) -> bool:
        """Remove channel by name.

        Args:
            channel_name: Name of channel to remove.

        Returns:
            True if removed.
        """
        for i, channel in enumerate(self._channels):
            if channel.name == channel_name:
                del self._channels[i]
                return True
        return False

    async def send(self, event: AlertEvent) -> dict[str, bool]:
        """Send alert to all channels.

        Args:
            event: Alert event to send.

        Returns:
            Dictionary of channel name -> success status.
        """
        if not self.enabled:
            return {}

        self._event_history.append(event)

        results = {}
        for channel in self._channels:
            try:
                success = await channel.send(event)
                results[channel.name] = success
            except Exception:
                results[channel.name] = False

        return results

    async def alert_critical(self, repo: RepoHealth) -> dict[str, bool]:
        """Send alert for critical repository status.

        Args:
            repo: Repository with critical status.

        Returns:
            Send results.
        """
        if not self.config.alert_on_critical:
            return {}

        event = AlertEvent(
            event_type=AlertEvent.CRITICAL_HEALTH,
            title=f"Critical: {repo.name}",
            message=f"Repository **{repo.name}** has critical health status.\n"
            f"Score: {repo.score:.0f}/100",
            severity="critical",
            repo=repo,
        )
        return await self.send(event)

    async def alert_build_failure(self, repo: RepoHealth) -> dict[str, bool]:
        """Send alert for build failure.

        Args:
            repo: Repository with failing build.

        Returns:
            Send results.
        """
        if not self.config.alert_on_build_failure:
            return {}

        workflow_name = repo.ci_status[0].workflow_name if repo.ci_status else "Unknown"

        event = AlertEvent(
            event_type=AlertEvent.BUILD_FAILURE,
            title=f"Build Failed: {repo.name}",
            message=f"Build failed for **{repo.name}**.\nWorkflow: {workflow_name}",
            severity="warning",
            repo=repo,
        )
        return await self.send(event)

    async def alert_vulnerability(
        self,
        repo: RepoHealth,
        min_severity: Severity | None = None,
    ) -> dict[str, bool]:
        """Send alert for security vulnerability.

        Args:
            repo: Repository with vulnerability.
            min_severity: Minimum severity to alert on (default: any).

        Returns:
            Send results.
        """
        if not self.config.alert_on_vulnerability:
            return {}

        if not repo.vulnerability_report:
            return {}

        vr = repo.vulnerability_report

        # Filter by minimum severity if specified
        if min_severity:
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            min_idx = severity_order.index(min_severity)
            relevant = sum(
                getattr(vr, f"{s.value}_count", 0) for s in severity_order[: min_idx + 1]
            )
            if relevant == 0:
                return {}

        alert_severity = "critical" if vr.critical_count > 0 else "warning"

        event = AlertEvent(
            event_type=AlertEvent.VULNERABILITY,
            title=f"Security Alert: {repo.name}",
            message=f"Security vulnerabilities found in **{repo.name}**.\n"
            f"Total: {vr.total_alerts} "
            f"(Critical: {vr.critical_count}, High: {vr.high_count})",
            severity=alert_severity,
            repo=repo,
            metadata={
                "total_alerts": vr.total_alerts,
                "critical": vr.critical_count,
                "high": vr.high_count,
            },
        )
        return await self.send(event)

    async def alert_scan_complete(
        self,
        summary: EcosystemSummary,
    ) -> dict[str, bool]:
        """Send alert for scan completion.

        Args:
            summary: Scan summary.

        Returns:
            Send results.
        """
        severity = "info"
        if summary.critical_count > 0:
            severity = "critical"
        elif summary.warning_count > 0:
            severity = "warning"

        event = AlertEvent(
            event_type=AlertEvent.SCAN_COMPLETE,
            title=f"Scan Complete: {summary.organization}",
            message=f"Ecosystem scan completed.\n"
            f"Repos: {summary.total_repos} | "
            f"Healthy: {summary.healthy_count} | "
            f"Warning: {summary.warning_count} | "
            f"Critical: {summary.critical_count}",
            severity=severity,
            metadata=summary.to_dict(),
        )
        return await self.send(event)

    async def process_summary(self, summary: EcosystemSummary) -> list[AlertEvent]:
        """Process summary and send appropriate alerts.

        Args:
            summary: Ecosystem summary to process.

        Returns:
            List of events sent.
        """
        events_sent = []

        # Check each repository for alert conditions
        for repo in summary.repos:
            # Critical status
            if repo.status == HealthStatus.CRITICAL:
                await self.alert_critical(repo)
                events_sent.append(
                    AlertEvent(
                        event_type=AlertEvent.CRITICAL_HEALTH,
                        title=f"Critical: {repo.name}",
                        message="",
                        severity="critical",
                        repo=repo,
                    )
                )

            # Build failures
            if repo.latest_build == BuildStatus.FAILING:
                await self.alert_build_failure(repo)
                events_sent.append(
                    AlertEvent(
                        event_type=AlertEvent.BUILD_FAILURE,
                        title=f"Build Failed: {repo.name}",
                        message="",
                        severity="warning",
                        repo=repo,
                    )
                )

            # Vulnerabilities
            if repo.vulnerability_report and repo.vulnerability_report.total_alerts > 0:
                await self.alert_vulnerability(repo)
                events_sent.append(
                    AlertEvent(
                        event_type=AlertEvent.VULNERABILITY,
                        title=f"Security: {repo.name}",
                        message="",
                        severity="warning"
                        if not repo.vulnerability_report.has_critical
                        else "critical",
                        repo=repo,
                    )
                )

        # Send scan complete summary
        await self.alert_scan_complete(summary)
        events_sent.append(
            AlertEvent(
                event_type=AlertEvent.SCAN_COMPLETE,
                title="Scan Complete",
                message="",
                severity="info",
            )
        )

        return events_sent


class ConsoleChannel(AlertChannel):
    """Console output channel for debugging/testing."""

    def __init__(self, color: bool = True) -> None:
        """Initialize console channel.

        Args:
            color: Whether to use colored output.
        """
        self.color = color

    @property
    def name(self) -> str:
        """Get channel name."""
        return "console"

    def is_configured(self) -> bool:
        """Console is always configured."""
        return True

    async def send(self, event: AlertEvent) -> bool:
        """Print alert to console.

        Args:
            event: Alert event to print.

        Returns:
            Always True.
        """
        colors = {
            "critical": "\033[91m",  # Red
            "warning": "\033[93m",  # Yellow
            "info": "\033[94m",  # Blue
            "success": "\033[92m",  # Green
        }
        reset = "\033[0m"

        color = colors.get(event.severity, "") if self.color else ""
        end = reset if self.color else ""

        print(f"{color}[{event.severity.upper()}]{end} {event.title}")
        print(f"  {event.message}")
        if event.repo:
            print(f"  Repository: {event.repo.name}")
        print()

        return True
