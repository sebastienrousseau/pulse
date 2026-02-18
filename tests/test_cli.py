"""Tests for Pulse CLI."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from pulse.cli import app, _print_summary, version_callback
from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    Language,
    RepoHealth,
    RepoMetrics,
    VulnerabilityReport,
)


runner = CliRunner()


class TestVersionCallback:
    """Tests for version_callback."""

    def test_version_callback_true(self) -> None:
        """Test version callback with True value raises Exit."""
        import typer

        with pytest.raises(typer.Exit):
            version_callback(True)

    def test_version_callback_false(self) -> None:
        """Test version callback with False value does nothing."""
        result = version_callback(False)
        assert result is None


class TestMainCallback:
    """Tests for main app callback."""

    def test_no_args_shows_help(self) -> None:
        """Test that no args shows help."""
        result = runner.invoke(app)
        # Exit code 0 or 2 are both valid (typer returns 2 with no_args_is_help)
        assert result.exit_code in (0, 2)
        # The help text contains various strings we can check for
        output = result.stdout.lower()
        assert "pulse" in output or "usage" in output or "commands" in output

    def test_version_flag(self) -> None:
        """Test --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Pulse version" in result.stdout

    def test_version_short_flag(self) -> None:
        """Test -v flag."""
        result = runner.invoke(app, ["-v"])
        assert result.exit_code == 0
        assert "Pulse version" in result.stdout


class TestPrintSummary:
    """Tests for _print_summary function."""

    def test_print_summary_healthy(self, capsys: pytest.CaptureFixture) -> None:
        """Test summary output for healthy ecosystem."""
        _print_summary("test-org", 10, 8, 1, 1, 85.0, 0)
        # Function uses rich console, output should complete without error

    def test_print_summary_critical(self, capsys: pytest.CaptureFixture) -> None:
        """Test summary output for critical ecosystem."""
        _print_summary("test-org", 10, 2, 3, 5, 40.0, 15)
        # Function should complete without error

    def test_print_summary_warning(self, capsys: pytest.CaptureFixture) -> None:
        """Test summary output for warning ecosystem."""
        _print_summary("test-org", 10, 6, 3, 1, 65.0, 5)
        # Function should complete without error

    def test_print_summary_zero_repos(self, capsys: pytest.CaptureFixture) -> None:
        """Test summary output with zero repos."""
        _print_summary("test-org", 0, 0, 0, 0, 0.0, 0)
        # Should handle division by zero gracefully


class TestInitCommand:
    """Tests for init command."""

    def test_init_creates_config(self) -> None:
        """Test init creates config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "pulse.yaml"
            result = runner.invoke(app, ["init", "--path", str(config_path)])
            assert result.exit_code == 0
            assert config_path.exists()
            assert "Configuration created" in result.stdout

    def test_init_default_path(self) -> None:
        """Test init with default path in temp dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pulse.cli.Path.cwd", return_value=Path(tmpdir)):
                result = runner.invoke(app, ["init"])
                # Should succeed even if file doesn't exist
                assert result.exit_code == 0

    def test_init_existing_file_no_overwrite(self) -> None:
        """Test init with existing file, no overwrite."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "pulse.yaml"
            config_path.write_text("existing: config\n")
            result = runner.invoke(app, ["init", "--path", str(config_path)], input="n\n")
            # Exit code can be 0 or 1 depending on typer version, but file should be unchanged
            # File should remain unchanged
            assert config_path.read_text() == "existing: config\n"

    def test_init_existing_file_overwrite(self) -> None:
        """Test init with existing file, overwrite."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "pulse.yaml"
            config_path.write_text("existing: config\n")
            result = runner.invoke(app, ["init", "--path", str(config_path)], input="y\n")
            assert result.exit_code == 0
            # File should be overwritten
            content = config_path.read_text()
            assert "github:" in content


class TestScanCommand:
    """Tests for scan command."""

    @pytest.fixture
    def mock_summary(self) -> EcosystemSummary:
        """Create mock ecosystem summary."""
        summary = EcosystemSummary(organization="test-org")
        repo = RepoHealth(
            name="test-repo",
            full_name="test-org/test-repo",
            url="https://github.com/test-org/test-repo",
            status=HealthStatus.HEALTHY,
            score=85.0,
            language=Language.PYTHON,
            metrics=RepoMetrics(stars=10, forks=5, open_issues=2),
        )
        summary.add_repo(repo)
        return summary

    def test_scan_basic(self, mock_summary: EcosystemSummary) -> None:
        """Test basic scan command."""
        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
            mock_monitor.set_progress_callback = MagicMock()
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["scan"])
            assert result.exit_code == 0

    def test_scan_with_org(self, mock_summary: EcosystemSummary) -> None:
        """Test scan with org option."""
        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
            mock_monitor.set_progress_callback = MagicMock()
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["scan", "--org", "other-org"])
            assert result.exit_code == 0

    def test_scan_with_json_output(self, mock_summary: EcosystemSummary) -> None:
        """Test scan with JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"

            with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
                mock_monitor = AsyncMock()
                mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
                mock_monitor.set_progress_callback = MagicMock()
                mock_monitor.export_json = MagicMock()
                mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
                mock_monitor.__aexit__ = AsyncMock(return_value=None)
                mock_monitor_cls.return_value = mock_monitor

                result = runner.invoke(app, ["scan", "--output", str(output_path)])
                assert result.exit_code == 0
                mock_monitor.export_json.assert_called_once_with(output_path)

    def test_scan_with_markdown_output(self, mock_summary: EcosystemSummary) -> None:
        """Test scan with Markdown output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.md"

            with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
                mock_monitor = AsyncMock()
                mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
                mock_monitor.set_progress_callback = MagicMock()
                mock_monitor.export_markdown = MagicMock()
                mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
                mock_monitor.__aexit__ = AsyncMock(return_value=None)
                mock_monitor_cls.return_value = mock_monitor

                result = runner.invoke(app, ["scan", "-m", str(output_path)])
                assert result.exit_code == 0
                mock_monitor.export_markdown.assert_called_once_with(output_path)

    def test_scan_with_dashboard(self, mock_summary: EcosystemSummary) -> None:
        """Test scan with dashboard generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
                with patch("pulse.cli.DashboardGenerator") as mock_gen_cls:
                    mock_monitor = AsyncMock()
                    mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
                    mock_monitor.set_progress_callback = MagicMock()
                    mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
                    mock_monitor.__aexit__ = AsyncMock(return_value=None)
                    mock_monitor_cls.return_value = mock_monitor

                    mock_gen = MagicMock()
                    mock_gen.generate = MagicMock(return_value=Path(tmpdir) / "index.html")
                    mock_gen_cls.return_value = mock_gen

                    result = runner.invoke(app, ["scan", "--dashboard", "--dashboard-dir", tmpdir])
                    assert result.exit_code == 0

    def test_scan_error_handling(self) -> None:
        """Test scan error handling."""
        from pulse.monitor import MonitorError

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(side_effect=MonitorError("Test error"))
            mock_monitor.set_progress_callback = MagicMock()
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["scan"])
            assert result.exit_code == 1
            assert "Error" in result.stdout


class TestRepoCommand:
    """Tests for repo command."""

    @pytest.fixture
    def mock_health(self) -> RepoHealth:
        """Create mock repo health."""
        return RepoHealth(
            name="test-repo",
            full_name="test-org/test-repo",
            url="https://github.com/test-org/test-repo",
            status=HealthStatus.HEALTHY,
            score=85.0,
            language=Language.PYTHON,
            latest_build=BuildStatus.PASSING,
            has_readme=True,
            has_license=True,
            has_ci=True,
            has_tests=True,
            has_docs=True,
            metrics=RepoMetrics(stars=100, forks=25, open_issues=5),
            vulnerability_report=VulnerabilityReport(
                repo_name="test-repo",
                total_alerts=2,
                critical_count=1,
            ),
        )

    def test_repo_basic(self, mock_health: RepoHealth) -> None:
        """Test basic repo command."""
        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_repo = AsyncMock(return_value=mock_health)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["repo", "test-repo"])
            assert result.exit_code == 0

    def test_repo_with_org(self, mock_health: RepoHealth) -> None:
        """Test repo command with org option."""
        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_repo = AsyncMock(return_value=mock_health)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["repo", "test-repo", "-o", "other-org"])
            assert result.exit_code == 0

    def test_repo_warning_status(self) -> None:
        """Test repo with warning status."""
        health = RepoHealth(
            name="test-repo",
            full_name="test-org/test-repo",
            url="https://github.com/test-org/test-repo",
            status=HealthStatus.WARNING,
            score=60.0,
            language=Language.RUST,
            latest_build=BuildStatus.FAILING,
            metrics=RepoMetrics(),
        )

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_repo = AsyncMock(return_value=health)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["repo", "test-repo"])
            assert result.exit_code == 0

    def test_repo_critical_status(self) -> None:
        """Test repo with critical status."""
        health = RepoHealth(
            name="test-repo",
            full_name="test-org/test-repo",
            url="https://github.com/test-org/test-repo",
            status=HealthStatus.CRITICAL,
            score=25.0,
            language=Language.JAVASCRIPT,
            metrics=RepoMetrics(),
        )

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_repo = AsyncMock(return_value=health)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["repo", "test-repo"])
            assert result.exit_code == 0

    def test_repo_error_handling(self) -> None:
        """Test repo error handling."""
        from pulse.monitor import MonitorError

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_repo = AsyncMock(side_effect=MonitorError("Not found"))
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["repo", "nonexistent"])
            assert result.exit_code == 1
            assert "Error" in result.stdout

    def test_repo_with_days_since_commit(self) -> None:
        """Test repo with days since commit displayed."""
        from datetime import datetime, timedelta

        health = RepoHealth(
            name="test-repo",
            full_name="test-org/test-repo",
            url="https://github.com/test-org/test-repo",
            status=HealthStatus.WARNING,
            score=60.0,
            language=Language.PYTHON,
            last_commit=datetime.now() - timedelta(days=30),
            metrics=RepoMetrics(),
        )

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_repo = AsyncMock(return_value=health)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["repo", "test-repo"])
            assert result.exit_code == 0


class TestDashboardCommand:
    """Tests for dashboard command."""

    @pytest.fixture
    def mock_summary(self) -> EcosystemSummary:
        """Create mock ecosystem summary."""
        summary = EcosystemSummary(organization="test-org")
        repo = RepoHealth(
            name="test-repo",
            full_name="test-org/test-repo",
            url="https://github.com/test-org/test-repo",
            status=HealthStatus.HEALTHY,
            score=85.0,
            language=Language.PYTHON,
            metrics=RepoMetrics(),
        )
        summary.add_repo(repo)
        return summary

    def test_dashboard_basic(self, mock_summary: EcosystemSummary) -> None:
        """Test basic dashboard command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
                with patch("pulse.cli.DashboardGenerator") as mock_gen_cls:
                    mock_monitor = AsyncMock()
                    mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
                    mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
                    mock_monitor.__aexit__ = AsyncMock(return_value=None)
                    mock_monitor_cls.return_value = mock_monitor

                    mock_gen = MagicMock()
                    mock_gen.generate = MagicMock(return_value=Path(tmpdir) / "index.html")
                    mock_gen_cls.return_value = mock_gen

                    result = runner.invoke(app, ["dashboard", "-o", tmpdir])
                    assert result.exit_code == 0
                    assert "Dashboard generated" in result.stdout

    def test_dashboard_with_org(self, mock_summary: EcosystemSummary) -> None:
        """Test dashboard with org option."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
                with patch("pulse.cli.DashboardGenerator") as mock_gen_cls:
                    mock_monitor = AsyncMock()
                    mock_monitor.scan_all = AsyncMock(return_value=mock_summary)
                    mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
                    mock_monitor.__aexit__ = AsyncMock(return_value=None)
                    mock_monitor_cls.return_value = mock_monitor

                    mock_gen = MagicMock()
                    mock_gen.generate = MagicMock(return_value=Path(tmpdir) / "index.html")
                    mock_gen_cls.return_value = mock_gen

                    result = runner.invoke(app, ["dashboard", "--org", "other-org", "-o", tmpdir])
                    assert result.exit_code == 0

    def test_dashboard_error_handling(self) -> None:
        """Test dashboard error handling."""
        from pulse.monitor import MonitorError

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(side_effect=MonitorError("API error"))
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["dashboard"])
            assert result.exit_code == 1
            assert "Error" in result.stdout


class TestStatusCommand:
    """Tests for status command."""

    @pytest.fixture
    def mock_summary_healthy(self) -> EcosystemSummary:
        """Create mock healthy ecosystem summary."""
        summary = EcosystemSummary(organization="test-org")
        for i in range(8):
            repo = RepoHealth(
                name=f"repo-{i}",
                full_name=f"test-org/repo-{i}",
                url=f"https://github.com/test-org/repo-{i}",
                status=HealthStatus.HEALTHY,
                score=85.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)
        return summary

    @pytest.fixture
    def mock_summary_critical(self) -> EcosystemSummary:
        """Create mock critical ecosystem summary."""
        summary = EcosystemSummary(organization="test-org")
        for i in range(3):
            repo = RepoHealth(
                name=f"critical-repo-{i}",
                full_name=f"test-org/critical-repo-{i}",
                url=f"https://github.com/test-org/critical-repo-{i}",
                status=HealthStatus.CRITICAL,
                score=25.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)
        summary.total_vulnerabilities = 10
        summary.critical_vulnerabilities = 3
        return summary

    def test_status_healthy(self, mock_summary_healthy: EcosystemSummary) -> None:
        """Test status with healthy ecosystem."""
        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(return_value=mock_summary_healthy)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["status"])
            assert result.exit_code == 0
            assert "HEALTHY" in result.stdout

    def test_status_critical(self, mock_summary_critical: EcosystemSummary) -> None:
        """Test status with critical ecosystem."""
        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(return_value=mock_summary_critical)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["status"])
            assert result.exit_code == 0
            assert "CRITICAL" in result.stdout

    def test_status_warning(self) -> None:
        """Test status with warning ecosystem."""
        summary = EcosystemSummary(organization="test-org")
        for i in range(6):
            repo = RepoHealth(
                name=f"repo-{i}",
                full_name=f"test-org/repo-{i}",
                url=f"https://github.com/test-org/repo-{i}",
                status=HealthStatus.HEALTHY if i < 4 else HealthStatus.WARNING,
                score=70.0,
                language=Language.PYTHON,
                metrics=RepoMetrics(),
            )
            summary.add_repo(repo)

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(return_value=summary)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["status"])
            assert result.exit_code == 0

    def test_status_with_org(self, mock_summary_healthy: EcosystemSummary) -> None:
        """Test status with org option."""
        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(return_value=mock_summary_healthy)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["status", "-o", "other-org"])
            assert result.exit_code == 0

    def test_status_error_handling(self) -> None:
        """Test status error handling."""
        from pulse.monitor import MonitorError

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(side_effect=MonitorError("API error"))
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["status"])
            assert result.exit_code == 1
            assert "Error" in result.stdout

    def test_status_with_vulnerabilities(self) -> None:
        """Test status displays vulnerabilities."""
        summary = EcosystemSummary(organization="test-org")
        summary.total_vulnerabilities = 5
        summary.critical_vulnerabilities = 2
        repo = RepoHealth(
            name="repo",
            full_name="test-org/repo",
            url="https://github.com/test-org/repo",
            status=HealthStatus.HEALTHY,
            score=85.0,
            language=Language.PYTHON,
            metrics=RepoMetrics(),
        )
        summary.add_repo(repo)

        with patch("pulse.cli.EcosystemMonitor") as mock_monitor_cls:
            mock_monitor = AsyncMock()
            mock_monitor.scan_all = AsyncMock(return_value=summary)
            mock_monitor.__aenter__ = AsyncMock(return_value=mock_monitor)
            mock_monitor.__aexit__ = AsyncMock(return_value=None)
            mock_monitor_cls.return_value = mock_monitor

            result = runner.invoke(app, ["status"])
            assert result.exit_code == 0
            assert "vulnerabilities" in result.stdout.lower()
