"""Command-line interface for Pulse."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from pulse import __version__
from pulse.config import PulseConfig, generate_default_config
from pulse.dashboard import DashboardGenerator
from pulse.models import HealthStatus
from pulse.monitor import EcosystemMonitor, MonitorError

app = typer.Typer(
    name="pulse",
    help="Ecosystem health monitoring and dashboard",
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"Pulse version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Pulse - Ecosystem health monitoring."""
    pass


@app.command()
def scan(
    org: Optional[str] = typer.Option(
        None,
        "--org",
        "-o",
        help="GitHub organization to scan.",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Output JSON file path.",
    ),
    markdown: Optional[Path] = typer.Option(
        None,
        "--markdown",
        "-m",
        help="Output Markdown report path.",
    ),
    dashboard: bool = typer.Option(
        False,
        "--dashboard",
        "-d",
        help="Generate HTML dashboard.",
    ),
    dashboard_dir: Optional[Path] = typer.Option(
        None,
        "--dashboard-dir",
        help="Dashboard output directory.",
    ),
) -> None:
    """Scan all repositories and generate health report."""
    pulse_config = PulseConfig.load(config)

    async def run_scan() -> None:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning repositories...", total=None)

            def on_progress(repo: str, current: int, total: int) -> None:
                progress.update(
                    task,
                    description=f"Scanning {repo} ({current}/{total})",
                )

            async with EcosystemMonitor(pulse_config, org) as monitor:
                monitor.set_progress_callback(on_progress)

                try:
                    summary = await monitor.scan_all()
                except MonitorError as e:
                    console.print(f"[red]Error:[/red] {e}")
                    raise typer.Exit(1)

                progress.update(task, description="Scan complete!")

        # Display summary
        console.print()
        _print_summary(summary.organization, summary.total_repos, summary.healthy_count,
                      summary.warning_count, summary.critical_count, summary.average_score,
                      summary.total_vulnerabilities)

        # Export if requested
        if output:
            monitor.export_json(output)
            console.print(f"\n[green]JSON report saved to:[/green] {output}")

        if markdown:
            monitor.export_markdown(markdown)
            console.print(f"[green]Markdown report saved to:[/green] {markdown}")

        if dashboard:
            generator = DashboardGenerator(pulse_config)
            path = generator.generate(summary, dashboard_dir)
            console.print(f"[green]Dashboard generated at:[/green] {path}")

    asyncio.run(run_scan())


def _print_summary(
    org: str,
    total: int,
    healthy: int,
    warning: int,
    critical: int,
    avg_score: float,
    vulns: int,
) -> None:
    """Print scan summary table."""
    table = Table(title=f"Ecosystem Health: {org}")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total Repositories", str(total))
    table.add_row("Healthy", f"[green]{healthy}[/green]")
    table.add_row("Warning", f"[yellow]{warning}[/yellow]")
    table.add_row("Critical", f"[red]{critical}[/red]")
    table.add_row("Average Score", f"{avg_score:.1f}/100")
    table.add_row("Vulnerabilities", f"[red]{vulns}[/red]" if vulns > 0 else "0")

    health_pct = (healthy / total * 100) if total > 0 else 0
    status = "[green]Good[/green]" if health_pct >= 80 else (
        "[yellow]Needs Attention[/yellow]" if health_pct >= 50 else "[red]Critical[/red]"
    )
    table.add_row("Overall Status", status)

    console.print(table)


@app.command()
def repo(
    name: str = typer.Argument(..., help="Repository name to scan."),
    org: Optional[str] = typer.Option(
        None,
        "--org",
        "-o",
        help="GitHub organization.",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file.",
    ),
) -> None:
    """Scan a single repository."""
    pulse_config = PulseConfig.load(config)

    async def run_scan() -> None:
        with console.status(f"Scanning {name}..."):
            async with EcosystemMonitor(pulse_config, org) as monitor:
                try:
                    health = await monitor.scan_repo(name)
                except MonitorError as e:
                    console.print(f"[red]Error:[/red] {e}")
                    raise typer.Exit(1)

        # Display results
        status_color = {
            HealthStatus.HEALTHY: "green",
            HealthStatus.WARNING: "yellow",
            HealthStatus.CRITICAL: "red",
        }.get(health.status, "white")

        table = Table(title=f"Repository: {health.full_name}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")

        table.add_row("Status", f"[{status_color}]{health.status.value}[/{status_color}]")
        table.add_row("Health Score", f"{health.score:.1f}/100")
        table.add_row("Language", health.language.value)
        table.add_row("Build Status", health.latest_build.value)
        table.add_row("Stars", str(health.metrics.stars))
        table.add_row("Forks", str(health.metrics.forks))
        table.add_row("Open Issues", str(health.metrics.open_issues))

        if health.vulnerability_report:
            vr = health.vulnerability_report
            table.add_row(
                "Vulnerabilities",
                f"[red]{vr.total_alerts}[/red] ({vr.critical_count} critical)"
                if vr.total_alerts > 0
                else "[green]0[/green]",
            )

        if health.days_since_commit is not None:
            table.add_row("Days Since Commit", str(health.days_since_commit))

        console.print(table)

        # Quality indicators
        console.print("\n[bold]Quality Indicators:[/bold]")
        indicators = [
            ("README", health.has_readme),
            ("LICENSE", health.has_license),
            ("CI/CD", health.has_ci),
            ("Tests", health.has_tests),
            ("Docs", health.has_docs),
        ]
        for label, has in indicators:
            icon = "[green]✓[/green]" if has else "[red]✗[/red]"
            console.print(f"  {icon} {label}")

    asyncio.run(run_scan())


@app.command()
def dashboard(
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Dashboard output directory.",
    ),
    org: Optional[str] = typer.Option(
        None,
        "--org",
        help="GitHub organization.",
    ),
    serve: bool = typer.Option(
        False,
        "--serve",
        "-s",
        help="Start local server after generation.",
    ),
    port: int = typer.Option(
        8080,
        "--port",
        "-p",
        help="Server port (with --serve).",
    ),
) -> None:
    """Generate health dashboard."""
    pulse_config = PulseConfig.load(config)

    async def run() -> None:
        console.print("[bold]Generating dashboard...[/bold]")

        with console.status("Scanning repositories..."):
            async with EcosystemMonitor(pulse_config, org) as monitor:
                try:
                    summary = await monitor.scan_all()
                except MonitorError as e:
                    console.print(f"[red]Error:[/red] {e}")
                    raise typer.Exit(1)

        generator = DashboardGenerator(pulse_config)
        path = generator.generate(summary, output)

        console.print(f"[green]Dashboard generated:[/green] {path}")

        if serve:
            import http.server
            import socketserver
            import webbrowser

            dashboard_dir = path.parent

            class Handler(http.server.SimpleHTTPRequestHandler):
                def __init__(self, *args: object, **kwargs: object) -> None:
                    super().__init__(*args, directory=str(dashboard_dir), **kwargs)  # type: ignore

            console.print(f"\n[bold]Starting server at http://localhost:{port}[/bold]")
            console.print("Press Ctrl+C to stop\n")

            webbrowser.open(f"http://localhost:{port}")

            with socketserver.TCPServer(("", port), Handler) as httpd:
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    console.print("\n[yellow]Server stopped[/yellow]")

    asyncio.run(run())


@app.command()
def init(
    path: Optional[Path] = typer.Option(
        None,
        "--path",
        "-p",
        help="Config file path.",
    ),
) -> None:
    """Initialize Pulse configuration."""
    if path is None:
        path = Path.cwd() / "pulse.yaml"

    if path.exists():
        overwrite = typer.confirm(f"{path} already exists. Overwrite?")
        if not overwrite:
            raise typer.Exit()

    generate_default_config(path)
    console.print(f"[green]Configuration created:[/green] {path}")
    console.print("\nEdit the file to configure your GitHub token and preferences.")


@app.command()
def status(
    org: Optional[str] = typer.Option(
        None,
        "--org",
        "-o",
        help="GitHub organization.",
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file.",
    ),
) -> None:
    """Quick status check of ecosystem health."""
    pulse_config = PulseConfig.load(config)

    async def run() -> None:
        async with EcosystemMonitor(pulse_config, org) as monitor:
            with console.status("Checking status..."):
                try:
                    summary = await monitor.scan_all()
                except MonitorError as e:
                    console.print(f"[red]Error:[/red] {e}")
                    raise typer.Exit(1)

        # Simple one-line status
        health_pct = summary.health_percentage

        if health_pct >= 80:
            status_str = "[green]HEALTHY[/green]"
        elif health_pct >= 50:
            status_str = "[yellow]WARNING[/yellow]"
        else:
            status_str = "[red]CRITICAL[/red]"

        console.print(
            f"\n{summary.organization}: {status_str} "
            f"({summary.healthy_count}/{summary.total_repos} repos healthy, "
            f"score: {summary.average_score:.0f}/100)"
        )

        if summary.critical_count > 0:
            console.print(f"\n[red]Critical repos ({summary.critical_count}):[/red]")
            for repo in [r for r in summary.repos if r.status == HealthStatus.CRITICAL]:
                console.print(f"  - {repo.name} (score: {repo.score:.0f})")

        if summary.total_vulnerabilities > 0:
            console.print(
                f"\n[yellow]Security:[/yellow] {summary.total_vulnerabilities} "
                f"vulnerabilities ({summary.critical_vulnerabilities} critical)"
            )

    asyncio.run(run())


if __name__ == "__main__":
    app()
