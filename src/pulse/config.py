"""Configuration management for Pulse."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class GitHubConfig(BaseModel):
    """GitHub API configuration."""

    token: str | None = Field(default=None, description="GitHub personal access token")
    api_url: str = Field(default="https://api.github.com", description="GitHub API base URL")
    organization: str = Field(
        default="sebastienrousseau", description="GitHub organization to monitor"
    )
    rate_limit_buffer: int = Field(
        default=100, description="Buffer to maintain before rate limit"
    )


class MonitoringConfig(BaseModel):
    """Monitoring behavior configuration."""

    scan_interval_minutes: int = Field(default=60, description="Interval between scans")
    include_archived: bool = Field(default=False, description="Include archived repositories")
    include_forks: bool = Field(default=False, description="Include forked repositories")
    include_private: bool = Field(default=True, description="Include private repositories")
    max_repos: int | None = Field(default=None, description="Maximum repos to scan (None=all)")
    languages: list[str] = Field(
        default_factory=lambda: ["rust", "python", "javascript", "typescript", "shell"],
        description="Languages to include in monitoring",
    )


class AlertConfig(BaseModel):
    """Alerting configuration."""

    enabled: bool = Field(default=True, description="Enable alerting")
    slack_webhook: str | None = Field(default=None, description="Slack webhook URL")
    email_recipients: list[str] = Field(default_factory=list, description="Email recipients")
    alert_on_critical: bool = Field(default=True, description="Alert on critical issues")
    alert_on_build_failure: bool = Field(default=True, description="Alert on build failures")
    alert_on_vulnerability: bool = Field(default=True, description="Alert on new vulnerabilities")


class DashboardConfig(BaseModel):
    """Dashboard configuration."""

    output_dir: Path = Field(
        default=Path("./dashboard"), description="Dashboard output directory"
    )
    template_dir: Path | None = Field(default=None, description="Custom template directory")
    theme: str = Field(default="dark", description="Dashboard theme (dark/light)")
    refresh_interval_seconds: int = Field(
        default=300, description="Auto-refresh interval for dashboard"
    )


class CacheConfig(BaseModel):
    """Caching configuration."""

    enabled: bool = Field(default=True, description="Enable caching")
    directory: Path = Field(default=Path("~/.cache/pulse"), description="Cache directory")
    ttl_seconds: int = Field(default=3600, description="Cache TTL in seconds")
    max_size_mb: int = Field(default=100, description="Maximum cache size in MB")


class PulseConfig(BaseModel):
    """Main Pulse configuration."""

    github: GitHubConfig = Field(default_factory=GitHubConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)

    @classmethod
    def load(cls, path: Path | str | None = None) -> PulseConfig:
        """Load configuration from file.

        Args:
            path: Path to config file. If None, searches default locations.

        Returns:
            PulseConfig instance.
        """
        if path is None:
            path = cls._find_config_file()

        if path is None:
            return cls()

        path = Path(path)
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls._from_dict(data)

    @classmethod
    def _find_config_file(cls) -> Path | None:
        """Find config file in default locations."""
        search_paths = [
            Path.cwd() / "pulse.yaml",
            Path.cwd() / "pulse.yml",
            Path.cwd() / ".pulse.yaml",
            Path.home() / ".config" / "pulse" / "config.yaml",
            Path.home() / ".pulse.yaml",
        ]

        for path in search_paths:
            if path.exists():
                return path

        return None

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> PulseConfig:
        """Create config from dictionary."""
        return cls(
            github=GitHubConfig(**data.get("github", {})),
            monitoring=MonitoringConfig(**data.get("monitoring", {})),
            alerts=AlertConfig(**data.get("alerts", {})),
            dashboard=DashboardConfig(**data.get("dashboard", {})),
            cache=CacheConfig(**data.get("cache", {})),
        )

    def save(self, path: Path | str) -> None:
        """Save configuration to file.

        Args:
            path: Path to save config file.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "github": self.github.model_dump(exclude_none=True),
            "monitoring": self.monitoring.model_dump(exclude_none=True),
            "alerts": self.alerts.model_dump(exclude_none=True),
            "dashboard": {
                k: str(v) if isinstance(v, Path) else v
                for k, v in self.dashboard.model_dump(exclude_none=True).items()
            },
            "cache": {
                k: str(v) if isinstance(v, Path) else v
                for k, v in self.cache.model_dump(exclude_none=True).items()
            },
        }

        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def get_github_token(self) -> str | None:
        """Get GitHub token from config, environment, or gh CLI.

        Returns:
            GitHub token or None if not configured.
        """
        import subprocess

        # Config takes precedence
        if self.github.token:
            return self.github.token

        # Fall back to environment variables
        for env_var in ["GITHUB_TOKEN", "GH_TOKEN", "PULSE_GITHUB_TOKEN"]:
            token = os.environ.get(env_var)
            if token:
                return token

        # Fall back to gh CLI auth token
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return None

    def validate_github_config(self) -> bool:
        """Validate GitHub configuration.

        Returns:
            True if configuration is valid.
        """
        return self.get_github_token() is not None


# Default configuration template
DEFAULT_CONFIG_TEMPLATE = """# Pulse Configuration
# Ecosystem health monitoring settings

github:
  # GitHub personal access token (or set GITHUB_TOKEN env var)
  # token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  organization: sebastienrousseau
  api_url: https://api.github.com

monitoring:
  scan_interval_minutes: 60
  include_archived: false
  include_forks: false
  include_private: true
  languages:
    - rust
    - python
    - javascript
    - typescript
    - shell

alerts:
  enabled: true
  alert_on_critical: true
  alert_on_build_failure: true
  alert_on_vulnerability: true
  # slack_webhook: https://hooks.slack.com/services/xxx
  # email_recipients:
  #   - alerts@example.com

dashboard:
  output_dir: ./dashboard
  theme: dark
  refresh_interval_seconds: 300

cache:
  enabled: true
  directory: ~/.cache/pulse
  ttl_seconds: 3600
  max_size_mb: 100
"""


def generate_default_config(path: Path | str) -> None:
    """Generate default configuration file.

    Args:
        path: Path to write config file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        f.write(DEFAULT_CONFIG_TEMPLATE)
