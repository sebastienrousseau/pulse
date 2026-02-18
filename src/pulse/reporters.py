"""Report generators for Pulse.

Provides multiple output formats for ecosystem health reports,
including HTML, CSV, and structured data exports.
"""

from __future__ import annotations

import csv
import html
import io
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pulse.models import (
    BuildStatus,
    EcosystemSummary,
    HealthStatus,
    RepoHealth,
)


class ReporterError(Exception):
    """Reporter error."""

    pass


class Reporter(ABC):
    """Base class for report generators."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Get format name."""
        pass

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Get file extension."""
        pass

    @abstractmethod
    def generate(self, summary: EcosystemSummary) -> str:
        """Generate report content.

        Args:
            summary: Ecosystem summary.

        Returns:
            Report content as string.
        """
        pass

    def write(
        self,
        summary: EcosystemSummary,
        path: Path | str,
    ) -> None:
        """Write report to file.

        Args:
            summary: Ecosystem summary.
            path: Output file path.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        content = self.generate(summary)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)


class HTMLReporter(Reporter):
    """Generate HTML reports with styling.

    Produces self-contained HTML reports with embedded CSS for
    easy viewing in any browser.
    """

    STATUS_COLORS = {
        HealthStatus.HEALTHY: "#28a745",
        HealthStatus.WARNING: "#ffc107",
        HealthStatus.CRITICAL: "#dc3545",
        HealthStatus.UNKNOWN: "#6c757d",
    }

    BUILD_COLORS = {
        BuildStatus.PASSING: "#28a745",
        BuildStatus.FAILING: "#dc3545",
        BuildStatus.PENDING: "#ffc107",
        BuildStatus.UNKNOWN: "#6c757d",
    }

    @property
    def format_name(self) -> str:
        """Get format name."""
        return "html"

    @property
    def file_extension(self) -> str:
        """Get file extension."""
        return ".html"

    def generate(self, summary: EcosystemSummary) -> str:
        """Generate HTML report.

        Args:
            summary: Ecosystem summary.

        Returns:
            HTML content.
        """
        timestamp = summary.generated_at.strftime("%Y-%m-%d %H:%M:%S")

        # Sort repos by score descending
        sorted_repos = sorted(summary.repos, key=lambda r: -r.score)

        repo_rows = "\n".join(self._generate_repo_row(repo) for repo in sorted_repos)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ecosystem Health Report - {html.escape(summary.organization)}</title>
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            font-size: 28px;
            margin-bottom: 8px;
        }}
        .header .subtitle {{
            opacity: 0.8;
            font-size: 14px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card .label {{
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .stat-card .change {{
            font-size: 12px;
            margin-top: 4px;
        }}
        .section {{
            background: white;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            font-size: 18px;
            margin-bottom: 16px;
            color: #1a1a2e;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #666;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
            color: white;
        }}
        .score-bar {{
            width: 100px;
            height: 8px;
            background: #eee;
            border-radius: 4px;
            overflow: hidden;
        }}
        .score-bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }}
        .footer {{
            text-align: center;
            color: #999;
            font-size: 12px;
            padding: 20px;
        }}
        a {{
            color: #0066cc;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .language-tag {{
            display: inline-block;
            padding: 2px 8px;
            background: #e9ecef;
            border-radius: 4px;
            font-size: 11px;
            color: #495057;
        }}
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            table {{
                display: block;
                overflow-x: auto;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Ecosystem Health Report</h1>
            <div class="subtitle">
                {html.escape(summary.organization)} &bull; Generated: {timestamp}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Repositories</div>
                <div class="value">{summary.total_repos}</div>
            </div>
            <div class="stat-card">
                <div class="label">Health Score</div>
                <div class="value">{summary.average_score:.0f}</div>
            </div>
            <div class="stat-card">
                <div class="label">Healthy</div>
                <div class="value" style="color: #28a745;">{summary.healthy_count}</div>
            </div>
            <div class="stat-card">
                <div class="label">Critical</div>
                <div class="value" style="color: #dc3545;">{summary.critical_count}</div>
            </div>
            <div class="stat-card">
                <div class="label">Vulnerabilities</div>
                <div class="value" style="color: {"#dc3545" if summary.total_vulnerabilities > 0 else "#28a745"};">
                    {summary.total_vulnerabilities}
                </div>
            </div>
            <div class="stat-card">
                <div class="label">Total Stars</div>
                <div class="value">{summary.total_stars:,}</div>
            </div>
        </div>

        <div class="section">
            <h2>Repository Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Repository</th>
                        <th>Language</th>
                        <th>Status</th>
                        <th>Score</th>
                        <th>Build</th>
                        <th>Vulns</th>
                        <th>Stars</th>
                    </tr>
                </thead>
                <tbody>
                    {repo_rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by Pulse Ecosystem Monitor
        </div>
    </div>
</body>
</html>"""

    def _generate_repo_row(self, repo: RepoHealth) -> str:
        """Generate table row for repository."""
        status_color = self.STATUS_COLORS.get(repo.status, "#6c757d")
        build_color = self.BUILD_COLORS.get(repo.latest_build, "#6c757d")

        score_color = (
            "#28a745" if repo.score >= 80 else "#ffc107" if repo.score >= 50 else "#dc3545"
        )

        vulns = repo.vulnerability_report.total_alerts if repo.vulnerability_report else 0
        vuln_style = "color: #dc3545; font-weight: bold;" if vulns > 0 else ""

        return f"""
            <tr>
                <td>
                    <a href="{html.escape(repo.url)}" target="_blank">
                        {html.escape(repo.name)}
                    </a>
                </td>
                <td>
                    <span class="language-tag">{html.escape(repo.language.value)}</span>
                </td>
                <td>
                    <span class="badge" style="background: {status_color};">
                        {html.escape(repo.status.value)}
                    </span>
                </td>
                <td>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <div class="score-bar">
                            <div class="score-bar-fill" style="width: {repo.score}%; background: {score_color};"></div>
                        </div>
                        <span>{repo.score:.0f}</span>
                    </div>
                </td>
                <td>
                    <span class="badge" style="background: {build_color};">
                        {html.escape(repo.latest_build.value)}
                    </span>
                </td>
                <td style="{vuln_style}">{vulns}</td>
                <td>{repo.metrics.stars:,}</td>
            </tr>
        """


class CSVReporter(Reporter):
    """Generate CSV reports for data analysis."""

    @property
    def format_name(self) -> str:
        """Get format name."""
        return "csv"

    @property
    def file_extension(self) -> str:
        """Get file extension."""
        return ".csv"

    def generate(self, summary: EcosystemSummary) -> str:
        """Generate CSV report.

        Args:
            summary: Ecosystem summary.

        Returns:
            CSV content.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(
            [
                "Repository",
                "Full Name",
                "URL",
                "Language",
                "Status",
                "Score",
                "Build Status",
                "Last Commit",
                "Days Since Commit",
                "Stars",
                "Forks",
                "Open Issues",
                "Vulnerabilities",
                "Critical Vulns",
                "High Vulns",
                "Has README",
                "Has License",
                "Has CI",
            ]
        )

        # Data rows
        for repo in sorted(summary.repos, key=lambda r: r.name):
            vulns = repo.vulnerability_report if repo.vulnerability_report else None
            writer.writerow(
                [
                    repo.name,
                    repo.full_name,
                    repo.url,
                    repo.language.value,
                    repo.status.value,
                    round(repo.score, 1),
                    repo.latest_build.value,
                    repo.last_commit.isoformat() if repo.last_commit else "",
                    repo.days_since_commit or "",
                    repo.metrics.stars,
                    repo.metrics.forks,
                    repo.metrics.open_issues,
                    vulns.total_alerts if vulns else 0,
                    vulns.critical_count if vulns else 0,
                    vulns.high_count if vulns else 0,
                    "Yes" if repo.has_readme else "No",
                    "Yes" if repo.has_license else "No",
                    "Yes" if repo.has_ci else "No",
                ]
            )

        return output.getvalue()


class JSONReporter(Reporter):
    """Generate JSON reports for API consumption."""

    def __init__(self, indent: int = 2, include_repos: bool = True) -> None:
        """Initialize JSON reporter.

        Args:
            indent: JSON indentation level.
            include_repos: Whether to include full repo details.
        """
        self.indent = indent
        self.include_repos = include_repos

    @property
    def format_name(self) -> str:
        """Get format name."""
        return "json"

    @property
    def file_extension(self) -> str:
        """Get file extension."""
        return ".json"

    def generate(self, summary: EcosystemSummary) -> str:
        """Generate JSON report.

        Args:
            summary: Ecosystem summary.

        Returns:
            JSON content.
        """
        data = {
            "meta": {
                "generated_at": summary.generated_at.isoformat(),
                "organization": summary.organization,
                "generator": "pulse",
                "version": "0.0.1",
            },
            "summary": {
                "total_repos": summary.total_repos,
                "healthy_count": summary.healthy_count,
                "warning_count": summary.warning_count,
                "critical_count": summary.critical_count,
                "health_percentage": round(summary.health_percentage, 1),
                "average_score": round(summary.average_score, 1),
                "total_stars": summary.total_stars,
                "total_forks": summary.total_forks,
                "total_open_issues": summary.total_open_issues,
                "total_vulnerabilities": summary.total_vulnerabilities,
                "critical_vulnerabilities": summary.critical_vulnerabilities,
                "language_breakdown": summary.language_breakdown,
            },
        }

        if self.include_repos:
            data["repositories"] = [self._repo_to_dict(repo) for repo in summary.repos]

        return json.dumps(data, indent=self.indent)

    def _repo_to_dict(self, repo: RepoHealth) -> dict[str, Any]:
        """Convert repository to dictionary."""
        vulns = repo.vulnerability_report

        return {
            "name": repo.name,
            "full_name": repo.full_name,
            "url": repo.url,
            "description": repo.description,
            "language": repo.language.value,
            "status": repo.status.value,
            "score": round(repo.score, 1),
            "build_status": repo.latest_build.value,
            "timestamps": {
                "last_commit": repo.last_commit.isoformat() if repo.last_commit else None,
                "last_release": repo.last_release.isoformat() if repo.last_release else None,
                "created_at": repo.created_at.isoformat() if repo.created_at else None,
            },
            "metrics": {
                "stars": repo.metrics.stars,
                "forks": repo.metrics.forks,
                "open_issues": repo.metrics.open_issues,
                "watchers": repo.metrics.watchers,
            },
            "security": {
                "total_alerts": vulns.total_alerts if vulns else 0,
                "critical": vulns.critical_count if vulns else 0,
                "high": vulns.high_count if vulns else 0,
                "medium": vulns.medium_count if vulns else 0,
                "low": vulns.low_count if vulns else 0,
            },
            "quality": {
                "has_readme": repo.has_readme,
                "has_license": repo.has_license,
                "has_ci": repo.has_ci,
                "has_tests": repo.has_tests,
            },
        }


class MarkdownReporter(Reporter):
    """Generate Markdown reports for documentation."""

    @property
    def format_name(self) -> str:
        """Get format name."""
        return "markdown"

    @property
    def file_extension(self) -> str:
        """Get file extension."""
        return ".md"

    def generate(self, summary: EcosystemSummary) -> str:
        """Generate Markdown report.

        Args:
            summary: Ecosystem summary.

        Returns:
            Markdown content.
        """
        timestamp = summary.generated_at.strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            "# Ecosystem Health Report",
            "",
            f"**Organization:** {summary.organization}",
            f"**Generated:** {timestamp}",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Repositories | {summary.total_repos} |",
            f"| Healthy | {summary.healthy_count} |",
            f"| Warning | {summary.warning_count} |",
            f"| Critical | {summary.critical_count} |",
            f"| Average Score | {summary.average_score:.1f}/100 |",
            f"| Total Stars | {summary.total_stars:,} |",
            f"| Open Issues | {summary.total_open_issues:,} |",
            f"| Vulnerabilities | {summary.total_vulnerabilities} |",
            "",
        ]

        # Language breakdown
        if summary.language_breakdown:
            lines.extend(
                [
                    "## Languages",
                    "",
                ]
            )
            for lang, count in sorted(summary.language_breakdown.items(), key=lambda x: -x[1]):
                lines.append(f"- **{lang}**: {count} repos")
            lines.append("")

        # Repository table
        lines.extend(
            [
                "## Repositories",
                "",
                "| Repository | Status | Score | Build | Vulns |",
                "|------------|--------|-------|-------|-------|",
            ]
        )

        status_emoji = {
            HealthStatus.HEALTHY: ":white_check_mark:",
            HealthStatus.WARNING: ":warning:",
            HealthStatus.CRITICAL: ":x:",
            HealthStatus.UNKNOWN: ":grey_question:",
        }

        for repo in sorted(summary.repos, key=lambda r: -r.score):
            emoji = status_emoji.get(repo.status, ":grey_question:")
            vulns = repo.vulnerability_report.total_alerts if repo.vulnerability_report else 0
            lines.append(
                f"| [{repo.name}]({repo.url}) | {emoji} {repo.status.value} | "
                f"{repo.score:.0f} | {repo.latest_build.value} | {vulns} |"
            )

        # Critical issues
        critical = [r for r in summary.repos if r.status == HealthStatus.CRITICAL]
        if critical:
            lines.extend(
                [
                    "",
                    "## Critical Issues",
                    "",
                ]
            )
            for repo in critical:
                lines.append(f"- **{repo.name}**: Score {repo.score:.0f}/100")

        # Vulnerabilities
        vulnerable = [
            r
            for r in summary.repos
            if r.vulnerability_report and r.vulnerability_report.total_alerts > 0
        ]
        if vulnerable:
            lines.extend(
                [
                    "",
                    "## Security Vulnerabilities",
                    "",
                ]
            )
            for repo in vulnerable:
                if repo.vulnerability_report:
                    vr = repo.vulnerability_report
                    lines.append(
                        f"- **{repo.name}**: {vr.total_alerts} alerts "
                        f"({vr.critical_count} critical, {vr.high_count} high)"
                    )

        lines.extend(
            [
                "",
                "---",
                "*Generated by Pulse Ecosystem Monitor*",
            ]
        )

        return "\n".join(lines)


class ReportFactory:
    """Factory for creating reporters."""

    _reporters: dict[str, type[Reporter]] = {
        "html": HTMLReporter,
        "csv": CSVReporter,
        "json": JSONReporter,
        "markdown": MarkdownReporter,
        "md": MarkdownReporter,
    }

    @classmethod
    def create(cls, format_name: str, **kwargs: Any) -> Reporter:
        """Create reporter by format name.

        Args:
            format_name: Format name (html, csv, json, markdown).
            **kwargs: Reporter-specific options.

        Returns:
            Reporter instance.

        Raises:
            ReporterError: If format is not supported.
        """
        reporter_cls = cls._reporters.get(format_name.lower())
        if not reporter_cls:
            supported = ", ".join(cls._reporters.keys())
            raise ReporterError(f"Unknown format: {format_name}. Supported: {supported}")

        return reporter_cls(**kwargs)

    @classmethod
    def supported_formats(cls) -> list[str]:
        """Get list of supported formats."""
        return list(cls._reporters.keys())

    @classmethod
    def register(cls, name: str, reporter_cls: type[Reporter]) -> None:
        """Register a custom reporter.

        Args:
            name: Format name.
            reporter_cls: Reporter class.
        """
        cls._reporters[name.lower()] = reporter_cls


def generate_all_reports(
    summary: EcosystemSummary,
    output_dir: Path | str,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Generate reports in multiple formats.

    Args:
        summary: Ecosystem summary.
        output_dir: Output directory.
        formats: List of formats (default: all).

    Returns:
        Dictionary of format -> output path.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if formats is None:
        formats = ["html", "csv", "json", "markdown"]

    results = {}
    for fmt in formats:
        try:
            reporter = ReportFactory.create(fmt)
            filename = f"report{reporter.file_extension}"
            path = output_dir / filename
            reporter.write(summary, path)
            results[fmt] = path
        except ReporterError:
            continue

    return results
