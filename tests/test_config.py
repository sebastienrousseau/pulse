"""Tests for Pulse configuration."""

import os
import tempfile
from pathlib import Path

from pulse.config import PulseConfig, generate_default_config


class TestPulseConfig:
    """Tests for PulseConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = PulseConfig()

        assert config.github.organization == "sebastienrousseau"
        assert config.github.api_url == "https://api.github.com"
        assert config.monitoring.scan_interval_minutes == 60
        assert config.monitoring.include_archived is False
        assert config.alerts.enabled is True

    def test_load_nonexistent(self) -> None:
        """Test loading from nonexistent file returns defaults."""
        config = PulseConfig.load("/nonexistent/path/config.yaml")
        assert config.github.organization == "sebastienrousseau"

    def test_save_and_load(self) -> None:
        """Test saving and loading configuration."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            path = Path(f.name)

        try:
            config = PulseConfig()
            config.github.organization = "test-org"
            config.monitoring.max_repos = 50
            config.save(path)

            loaded = PulseConfig.load(path)
            assert loaded.github.organization == "test-org"
            assert loaded.monitoring.max_repos == 50
        finally:
            path.unlink()

    def test_get_github_token_from_config(self) -> None:
        """Test getting token from config."""
        config = PulseConfig()
        config.github.token = "test-token"

        assert config.get_github_token() == "test-token"

    def test_get_github_token_from_env(self) -> None:
        """Test getting token from environment."""
        config = PulseConfig()
        config.github.token = None

        os.environ["GITHUB_TOKEN"] = "env-token"
        try:
            assert config.get_github_token() == "env-token"
        finally:
            del os.environ["GITHUB_TOKEN"]

    def test_get_github_token_none(self) -> None:
        """Test getting token when not configured."""
        config = PulseConfig()
        config.github.token = None

        # Ensure env vars are not set
        for var in ["GITHUB_TOKEN", "GH_TOKEN", "PULSE_GITHUB_TOKEN"]:
            os.environ.pop(var, None)

        assert config.get_github_token() is None

    def test_validate_github_config(self) -> None:
        """Test GitHub config validation."""
        config = PulseConfig()
        config.github.token = None

        # Clear env vars
        for var in ["GITHUB_TOKEN", "GH_TOKEN", "PULSE_GITHUB_TOKEN"]:
            os.environ.pop(var, None)

        assert config.validate_github_config() is False

        config.github.token = "test-token"
        assert config.validate_github_config() is True


class TestGenerateDefaultConfig:
    """Tests for generate_default_config."""

    def test_generate_default_config(self) -> None:
        """Test generating default config file."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            path = Path(f.name)

        try:
            # Remove the file first
            path.unlink()

            generate_default_config(path)

            assert path.exists()
            content = path.read_text()
            assert "github:" in content
            assert "monitoring:" in content
            assert "alerts:" in content
        finally:
            if path.exists():
                path.unlink()
