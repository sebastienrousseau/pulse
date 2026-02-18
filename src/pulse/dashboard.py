"""Dashboard generation for Pulse."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, PackageLoader, select_autoescape

if TYPE_CHECKING:
    from pulse.config import PulseConfig
    from pulse.models import EcosystemSummary


class DashboardGenerator:
    """Generate HTML dashboard from ecosystem summary.

    Creates a static HTML dashboard with health metrics, charts,
    and detailed repository information.

    Example:
        >>> generator = DashboardGenerator(config)
        >>> generator.generate(summary, output_dir="./dashboard")
    """

    def __init__(self, config: PulseConfig) -> None:
        """Initialize dashboard generator.

        Args:
            config: Pulse configuration.
        """
        self.config = config
        self._env: Environment | None = None

    def _get_env(self) -> Environment:
        """Get Jinja2 environment."""
        if self._env is None:
            try:
                self._env = Environment(
                    loader=PackageLoader("pulse", "templates"),
                    autoescape=select_autoescape(["html", "xml"]),
                )
            except ValueError:
                # Fallback if templates not found in package
                self._env = Environment(autoescape=select_autoescape(["html", "xml"]))
        return self._env

    def _generate_inline_dashboard(self, summary: EcosystemSummary) -> str:
        """Generate dashboard HTML inline without templates.

        Args:
            summary: Ecosystem summary data.

        Returns:
            HTML string.
        """
        theme = self.config.dashboard.theme
        bg_color = "#1a1a2e" if theme == "dark" else "#ffffff"
        text_color = "#eaeaea" if theme == "dark" else "#333333"
        card_bg = "#16213e" if theme == "dark" else "#f5f5f5"
        accent = "#0f3460" if theme == "dark" else "#e0e0e0"
        healthy_color = "#4caf50"
        warning_color = "#ff9800"
        critical_color = "#f44336"

        # Build repo rows
        repo_rows = []
        for repo in sorted(summary.repos, key=lambda r: -r.score):
            status_color = {
                "healthy": healthy_color,
                "warning": warning_color,
                "critical": critical_color,
            }.get(repo.status.value, "#888")

            vulns = (
                repo.vulnerability_report.total_alerts
                if repo.vulnerability_report
                else 0
            )

            repo_rows.append(f"""
                <tr>
                    <td><a href="{repo.url}" target="_blank" style="color: {text_color};">{repo.name}</a></td>
                    <td><span style="color: {status_color};">●</span> {repo.status.value}</td>
                    <td>{repo.score:.0f}</td>
                    <td>{repo.language.value}</td>
                    <td>{repo.latest_build.value}</td>
                    <td>{vulns}</td>
                    <td>{repo.metrics.stars}</td>
                    <td>{repo.metrics.open_issues}</td>
                </tr>
            """)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="{self.config.dashboard.refresh_interval_seconds}">
    <title>Pulse - Ecosystem Health Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: {bg_color};
            color: {text_color};
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        .subtitle {{ color: #888; margin-bottom: 2rem; }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: {card_bg};
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}
        .card-value {{ font-size: 2.5rem; font-weight: bold; }}
        .card-label {{ color: #888; margin-top: 0.5rem; }}
        .healthy {{ color: {healthy_color}; }}
        .warning {{ color: {warning_color}; }}
        .critical {{ color: {critical_color}; }}
        .section {{ margin-bottom: 2rem; }}
        .section-title {{
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid {accent};
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: {card_bg};
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{ padding: 1rem; text-align: left; }}
        th {{ background: {accent}; font-weight: 600; }}
        tr:hover {{ background: rgba(255,255,255,0.05); }}
        .progress-bar {{
            height: 20px;
            background: {accent};
            border-radius: 10px;
            overflow: hidden;
            margin: 1rem 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, {critical_color}, {warning_color}, {healthy_color});
            transition: width 0.3s ease;
        }}
        .lang-bar {{
            display: flex;
            height: 30px;
            border-radius: 4px;
            overflow: hidden;
            margin: 1rem 0;
        }}
        .lang-segment {{ display: flex; align-items: center; justify-content: center; color: white; font-size: 0.8rem; }}
        footer {{ text-align: center; padding: 2rem; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Pulse Dashboard</h1>
        <p class="subtitle">Ecosystem health monitoring for {summary.organization}</p>

        <div class="cards">
            <div class="card">
                <div class="card-value">{summary.total_repos}</div>
                <div class="card-label">Total Repositories</div>
            </div>
            <div class="card">
                <div class="card-value healthy">{summary.healthy_count}</div>
                <div class="card-label">Healthy</div>
            </div>
            <div class="card">
                <div class="card-value warning">{summary.warning_count}</div>
                <div class="card-label">Warning</div>
            </div>
            <div class="card">
                <div class="card-value critical">{summary.critical_count}</div>
                <div class="card-label">Critical</div>
            </div>
            <div class="card">
                <div class="card-value">{summary.average_score:.0f}</div>
                <div class="card-label">Avg Score</div>
            </div>
            <div class="card">
                <div class="card-value">{summary.total_vulnerabilities}</div>
                <div class="card-label">Vulnerabilities</div>
            </div>
            <div class="card">
                <div class="card-value">{summary.total_stars}</div>
                <div class="card-label">Total Stars</div>
            </div>
            <div class="card">
                <div class="card-value">{summary.total_open_issues}</div>
                <div class="card-label">Open Issues</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Health Distribution</h2>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {summary.health_percentage}%;"></div>
            </div>
            <p>{summary.health_percentage:.1f}% of repositories are healthy</p>
        </div>

        <div class="section">
            <h2 class="section-title">Repository Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Repository</th>
                        <th>Status</th>
                        <th>Score</th>
                        <th>Language</th>
                        <th>Build</th>
                        <th>Vulns</th>
                        <th>Stars</th>
                        <th>Issues</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(repo_rows)}
                </tbody>
            </table>
        </div>

        <footer>
            Generated by Pulse v0.0.1 at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>
</body>
</html>"""

        return html

    def generate(
        self,
        summary: EcosystemSummary,
        output_dir: Path | str | None = None,
    ) -> Path:
        """Generate HTML dashboard.

        Args:
            summary: Ecosystem summary to render.
            output_dir: Output directory. Defaults to config setting.

        Returns:
            Path to generated index.html.
        """
        if output_dir is None:
            output_dir = self.config.dashboard.output_dir

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate HTML
        html = self._generate_inline_dashboard(summary)

        # Write index.html
        index_path = output_dir / "index.html"
        with open(index_path, "w") as f:
            f.write(html)

        return index_path

    def generate_badge(
        self,
        summary: EcosystemSummary,
        output_path: Path | str,
    ) -> Path:
        """Generate SVG status badge.

        Args:
            summary: Ecosystem summary.
            output_path: Output path for badge SVG.

        Returns:
            Path to generated badge.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Determine color based on health
        if summary.health_percentage >= 80:
            color = "#4caf50"
            label = "healthy"
        elif summary.health_percentage >= 50:
            color = "#ff9800"
            label = "warning"
        else:
            color = "#f44336"
            label = "critical"

        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="150" height="20">
    <linearGradient id="b" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <mask id="a">
        <rect width="150" height="20" rx="3" fill="#fff"/>
    </mask>
    <g mask="url(#a)">
        <path fill="#555" d="M0 0h63v20H0z"/>
        <path fill="{color}" d="M63 0h87v20H63z"/>
        <path fill="url(#b)" d="M0 0h150v20H0z"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,sans-serif" font-size="11">
        <text x="31.5" y="15" fill="#010101" fill-opacity=".3">health</text>
        <text x="31.5" y="14">health</text>
        <text x="105.5" y="15" fill="#010101" fill-opacity=".3">{summary.health_percentage:.0f}% {label}</text>
        <text x="105.5" y="14">{summary.health_percentage:.0f}% {label}</text>
    </g>
</svg>"""

        with open(output_path, "w") as f:
            f.write(svg)

        return output_path
