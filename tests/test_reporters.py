"""Tests for reporters module."""

import json
import tempfile
from pathlib import Path

import pytest

from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    Language,
    RepoHealth,
    RepoMetrics,
    VulnerabilityReport,
)
from pulse.reporters import (
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
    ReporterError,
    ReportFactory,
    generate_all_reports,
)


@pytest.fixture
def sample_summary() -> EcosystemSummary:
    """Create sample ecosystem summary for testing."""
    summary = EcosystemSummary(organization="test-org")

    # Add repos
    repos = [
        RepoHealth(
            name="healthy-repo",
            full_name="test-org/healthy-repo",
            url="https://github.com/test-org/healthy-repo",
            status=HealthStatus.HEALTHY,
            score=90.0,
            language=Language.PYTHON,
            latest_build=BuildStatus.PASSING,
            has_readme=True,
            has_license=True,
            has_ci=True,
            metrics=RepoMetrics(stars=100, forks=20, open_issues=5),
        ),
        RepoHealth(
            name="warning-repo",
            full_name="test-org/warning-repo",
            url="https://github.com/test-org/warning-repo",
            status=HealthStatus.WARNING,
            score=65.0,
            language=Language.RUST,
            latest_build=BuildStatus.PASSING,
            has_readme=True,
            metrics=RepoMetrics(stars=50, forks=10, open_issues=15),
            vulnerability_report=VulnerabilityReport(
                repo_name="warning-repo",
                total_alerts=3,
                critical_count=0,
                high_count=2,
                medium_count=1,
            ),
        ),
        RepoHealth(
            name="critical-repo",
            full_name="test-org/critical-repo",
            url="https://github.com/test-org/critical-repo",
            status=HealthStatus.CRITICAL,
            score=30.0,
            language=Language.JAVASCRIPT,
            latest_build=BuildStatus.FAILING,
            metrics=RepoMetrics(stars=25, forks=5, open_issues=30),
            vulnerability_report=VulnerabilityReport(
                repo_name="critical-repo",
                total_alerts=8,
                critical_count=2,
                high_count=4,
                medium_count=2,
            ),
        ),
    ]

    for repo in repos:
        summary.add_repo(repo)

    return summary


class TestHTMLReporter:
    """Tests for HTMLReporter."""

    def test_format_name(self) -> None:
        """Test format name."""
        reporter = HTMLReporter()
        assert reporter.format_name == "html"
        assert reporter.file_extension == ".html"

    def test_generate(self, sample_summary: EcosystemSummary) -> None:
        """Test HTML generation."""
        reporter = HTMLReporter()
        html = reporter.generate(sample_summary)

        assert "<!DOCTYPE html>" in html
        assert "test-org" in html
        assert "healthy-repo" in html
        assert "warning-repo" in html
        assert "critical-repo" in html

    def test_generate_contains_stats(self, sample_summary: EcosystemSummary) -> None:
        """Test HTML contains stats."""
        reporter = HTMLReporter()
        html = reporter.generate(sample_summary)

        assert "Total Repositories" in html
        assert "Health Score" in html
        assert str(sample_summary.total_repos) in html

    def test_generate_contains_styling(self, sample_summary: EcosystemSummary) -> None:
        """Test HTML contains embedded CSS."""
        reporter = HTMLReporter()
        html = reporter.generate(sample_summary)

        assert "<style>" in html
        assert "font-family" in html

    def test_write(self, sample_summary: EcosystemSummary) -> None:
        """Test writing to file."""
        reporter = HTMLReporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.html"
            reporter.write(sample_summary, path)

            assert path.exists()
            content = path.read_text()
            assert "<!DOCTYPE html>" in content


class TestCSVReporter:
    """Tests for CSVReporter."""

    def test_format_name(self) -> None:
        """Test format name."""
        reporter = CSVReporter()
        assert reporter.format_name == "csv"
        assert reporter.file_extension == ".csv"

    def test_generate(self, sample_summary: EcosystemSummary) -> None:
        """Test CSV generation."""
        reporter = CSVReporter()
        csv = reporter.generate(sample_summary)

        lines = csv.strip().split("\n")
        assert len(lines) == 4  # Header + 3 repos

        # Check header
        header = lines[0]
        assert "Repository" in header
        assert "Status" in header
        assert "Score" in header

    def test_generate_data_rows(self, sample_summary: EcosystemSummary) -> None:
        """Test CSV data rows."""
        reporter = CSVReporter()
        csv = reporter.generate(sample_summary)

        assert "healthy-repo" in csv
        assert "critical" in csv.lower()
        assert "python" in csv.lower()

    def test_vulnerability_counts(self, sample_summary: EcosystemSummary) -> None:
        """Test vulnerability counts in CSV."""
        reporter = CSVReporter()
        csv = reporter.generate(sample_summary)

        # Critical repo has 2 critical vulns
        assert ",2," in csv or ",2\n" in csv


class TestJSONReporter:
    """Tests for JSONReporter."""

    def test_format_name(self) -> None:
        """Test format name."""
        reporter = JSONReporter()
        assert reporter.format_name == "json"
        assert reporter.file_extension == ".json"

    def test_generate_valid_json(self, sample_summary: EcosystemSummary) -> None:
        """Test valid JSON output."""
        reporter = JSONReporter()
        output = reporter.generate(sample_summary)

        # Should be valid JSON
        data = json.loads(output)
        assert "meta" in data
        assert "summary" in data
        assert "repositories" in data

    def test_generate_metadata(self, sample_summary: EcosystemSummary) -> None:
        """Test metadata in JSON."""
        reporter = JSONReporter()
        output = reporter.generate(sample_summary)
        data = json.loads(output)

        assert data["meta"]["organization"] == "test-org"
        assert data["meta"]["generator"] == "pulse"
        assert "generated_at" in data["meta"]

    def test_generate_summary(self, sample_summary: EcosystemSummary) -> None:
        """Test summary in JSON."""
        reporter = JSONReporter()
        output = reporter.generate(sample_summary)
        data = json.loads(output)

        summary = data["summary"]
        assert summary["total_repos"] == 3
        assert summary["healthy_count"] == 1
        assert summary["warning_count"] == 1
        assert summary["critical_count"] == 1

    def test_generate_repos(self, sample_summary: EcosystemSummary) -> None:
        """Test repository data in JSON."""
        reporter = JSONReporter()
        output = reporter.generate(sample_summary)
        data = json.loads(output)

        repos = data["repositories"]
        assert len(repos) == 3

        healthy = next(r for r in repos if r["name"] == "healthy-repo")
        assert healthy["score"] == 90.0
        assert healthy["status"] == "healthy"
        assert healthy["metrics"]["stars"] == 100

    def test_exclude_repos(self, sample_summary: EcosystemSummary) -> None:
        """Test excluding repo details."""
        reporter = JSONReporter(include_repos=False)
        output = reporter.generate(sample_summary)
        data = json.loads(output)

        assert "repositories" not in data


class TestMarkdownReporter:
    """Tests for MarkdownReporter."""

    def test_format_name(self) -> None:
        """Test format name."""
        reporter = MarkdownReporter()
        assert reporter.format_name == "markdown"
        assert reporter.file_extension == ".md"

    def test_generate(self, sample_summary: EcosystemSummary) -> None:
        """Test markdown generation."""
        reporter = MarkdownReporter()
        md = reporter.generate(sample_summary)

        assert "# Ecosystem Health Report" in md
        assert "test-org" in md

    def test_generate_summary_table(self, sample_summary: EcosystemSummary) -> None:
        """Test summary table in markdown."""
        reporter = MarkdownReporter()
        md = reporter.generate(sample_summary)

        assert "| Metric | Value |" in md
        assert "Total Repositories" in md
        assert "Average Score" in md

    def test_generate_repo_table(self, sample_summary: EcosystemSummary) -> None:
        """Test repository table in markdown."""
        reporter = MarkdownReporter()
        md = reporter.generate(sample_summary)

        assert "| Repository | Status | Score | Build | Vulns |" in md
        assert "[healthy-repo]" in md

    def test_generate_critical_section(self, sample_summary: EcosystemSummary) -> None:
        """Test critical issues section."""
        reporter = MarkdownReporter()
        md = reporter.generate(sample_summary)

        assert "## Critical Issues" in md
        assert "critical-repo" in md

    def test_generate_vulnerability_section(self, sample_summary: EcosystemSummary) -> None:
        """Test vulnerability section."""
        reporter = MarkdownReporter()
        md = reporter.generate(sample_summary)

        assert "## Security Vulnerabilities" in md


class TestReportFactory:
    """Tests for ReportFactory."""

    def test_create_html(self) -> None:
        """Test creating HTML reporter."""
        reporter = ReportFactory.create("html")
        assert isinstance(reporter, HTMLReporter)

    def test_create_csv(self) -> None:
        """Test creating CSV reporter."""
        reporter = ReportFactory.create("csv")
        assert isinstance(reporter, CSVReporter)

    def test_create_json(self) -> None:
        """Test creating JSON reporter."""
        reporter = ReportFactory.create("json")
        assert isinstance(reporter, JSONReporter)

    def test_create_markdown(self) -> None:
        """Test creating Markdown reporter."""
        reporter = ReportFactory.create("markdown")
        assert isinstance(reporter, MarkdownReporter)

        reporter2 = ReportFactory.create("md")
        assert isinstance(reporter2, MarkdownReporter)

    def test_create_case_insensitive(self) -> None:
        """Test case insensitive format names."""
        reporter1 = ReportFactory.create("HTML")
        reporter2 = ReportFactory.create("Json")
        reporter3 = ReportFactory.create("MARKDOWN")

        assert isinstance(reporter1, HTMLReporter)
        assert isinstance(reporter2, JSONReporter)
        assert isinstance(reporter3, MarkdownReporter)

    def test_create_unknown_format(self) -> None:
        """Test error on unknown format."""
        with pytest.raises(ReporterError) as exc_info:
            ReportFactory.create("xml")

        assert "Unknown format" in str(exc_info.value)
        assert "xml" in str(exc_info.value)

    def test_supported_formats(self) -> None:
        """Test getting supported formats."""
        formats = ReportFactory.supported_formats()

        assert "html" in formats
        assert "csv" in formats
        assert "json" in formats
        assert "markdown" in formats

    def test_create_with_options(self) -> None:
        """Test creating reporter with options."""
        reporter = ReportFactory.create("json", indent=4, include_repos=False)
        assert isinstance(reporter, JSONReporter)
        assert reporter.indent == 4
        assert reporter.include_repos is False


class TestGenerateAllReports:
    """Tests for generate_all_reports."""

    def test_generate_all(self, sample_summary: EcosystemSummary) -> None:
        """Test generating all report formats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            results = generate_all_reports(sample_summary, tmpdir)

            assert "html" in results
            assert "csv" in results
            assert "json" in results
            assert "markdown" in results

            # All files should exist
            for path in results.values():
                assert path.exists()

    def test_generate_specific_formats(self, sample_summary: EcosystemSummary) -> None:
        """Test generating specific formats."""
        with tempfile.TemporaryDirectory() as tmpdir:
            results = generate_all_reports(
                sample_summary,
                tmpdir,
                formats=["html", "json"],
            )

            assert "html" in results
            assert "json" in results
            assert "csv" not in results

    def test_creates_output_dir(self, sample_summary: EcosystemSummary) -> None:
        """Test creating output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "reports" / "nested"
            results = generate_all_reports(sample_summary, output_dir)

            assert output_dir.exists()
            assert len(results) == 4

    def test_skip_invalid_format(self, sample_summary: EcosystemSummary) -> None:
        """Test skipping invalid format gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            results = generate_all_reports(
                sample_summary,
                tmpdir,
                formats=["html", "invalid", "json"],
            )

            assert "html" in results
            assert "json" in results
            assert "invalid" not in results
