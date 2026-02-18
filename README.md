# Pulse

Ecosystem health monitoring and dashboard for the Sebastien Rousseau repository ecosystem.

## Overview

Pulse provides comprehensive monitoring, health scoring, and visualization for repositories across the ecosystem. It tracks:

- **Repository Health**: Overall health scores based on multiple factors
- **Build Status**: CI/CD pipeline status across all repos
- **Security**: Dependency vulnerabilities and security advisories
- **Activity**: Commit frequency and staleness detection
- **Quality**: Documentation, licensing, and best practices

## Features

- Real-time repository health scoring (0-100)
- Dependency vulnerability tracking via Dependabot
- Build status aggregation from GitHub Actions
- Interactive HTML dashboard with dark/light themes
- CLI for quick status checks
- JSON and Markdown export
- Configurable alerting thresholds
- Async API for efficient large-scale scanning

## Installation

```bash
pip install pulse
```

Or with development dependencies:

```bash
pip install pulse[dev]
```

## Quick Start

### CLI Usage

```bash
# Initialize configuration
pulse init

# Quick status check
pulse status

# Full scan with dashboard generation
pulse scan --dashboard

# Scan single repository
pulse repo shokunin

# Generate dashboard with local server
pulse dashboard --serve
```

### Python API

```python
import asyncio
from pulse import EcosystemMonitor, PulseConfig

async def main():
    config = PulseConfig.load()

    async with EcosystemMonitor(config) as monitor:
        # Scan all repositories
        summary = await monitor.scan_all()

        print(f"Total repos: {summary.total_repos}")
        print(f"Healthy: {summary.healthy_count}")
        print(f"Average score: {summary.average_score:.1f}")

        # Get repos needing attention
        for repo in monitor.get_repos_needing_attention():
            print(f"  - {repo.name}: {repo.score:.0f}/100")

asyncio.run(main())
```

## Configuration

Create a `pulse.yaml` configuration file:

```yaml
github:
  # Token from environment: GITHUB_TOKEN, GH_TOKEN, or PULSE_GITHUB_TOKEN
  organization: sebastienrousseau

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

dashboard:
  output_dir: ./dashboard
  theme: dark
  refresh_interval_seconds: 300
```

## Health Scoring

Repositories are scored on a 0-100 scale based on:

| Factor | Impact |
|--------|--------|
| Passing CI build | +15 |
| Failing CI build | -15 |
| README present | +5 |
| Documentation | +5 |
| License file | +5 |
| CI/CD configured | +5 |
| Tests present | +5 |
| Recent activity (<30 days) | +10 |
| Moderate activity (<90 days) | +5 |
| Stale (>365 days) | -10 |
| Security vulnerabilities | -20 max |
| Outdated dependencies | -10 max |

Status thresholds:
- **Healthy**: Score >= 80
- **Warning**: Score >= 50
- **Critical**: Score < 50

## CLI Commands

### `pulse scan`

Scan all repositories and generate reports.

```bash
pulse scan [OPTIONS]

Options:
  -o, --org TEXT          GitHub organization
  -c, --config PATH       Config file path
  --output PATH           Export to JSON
  -m, --markdown PATH     Export to Markdown
  -d, --dashboard         Generate HTML dashboard
  --dashboard-dir PATH    Dashboard output directory
```

### `pulse repo`

Scan a single repository.

```bash
pulse repo REPO_NAME [OPTIONS]

Options:
  -o, --org TEXT      GitHub organization
  -c, --config PATH   Config file path
```

### `pulse dashboard`

Generate and optionally serve the dashboard.

```bash
pulse dashboard [OPTIONS]

Options:
  -o, --output PATH   Output directory
  --org TEXT          GitHub organization
  -s, --serve         Start local server
  -p, --port INT      Server port (default: 8080)
```

### `pulse status`

Quick one-line status check.

```bash
pulse status [OPTIONS]

Options:
  -o, --org TEXT      GitHub organization
  -c, --config PATH   Config file path
```

### `pulse init`

Initialize configuration file.

```bash
pulse init [OPTIONS]

Options:
  -p, --path PATH     Config file path
```

## API Reference

### EcosystemMonitor

Main monitoring class for ecosystem health tracking.

```python
class EcosystemMonitor:
    def __init__(self, config: PulseConfig | None = None, org: str | None = None)

    async def scan_all(self) -> EcosystemSummary
    async def scan_repo(self, repo_name: str) -> RepoHealth
    async def scan_repos(self, repo_names: list[str]) -> EcosystemSummary

    def get_critical_repos(self) -> list[RepoHealth]
    def get_repos_needing_attention(self) -> list[RepoHealth]
    def get_vulnerable_repos(self) -> list[RepoHealth]
    def get_failing_builds(self) -> list[RepoHealth]
    def get_stale_repos(self, days: int = 90) -> list[RepoHealth]

    def export_json(self, path: Path | str) -> None
    def export_markdown(self, path: Path | str) -> None
```

### RepoHealth

Repository health assessment model.

```python
class RepoHealth:
    name: str
    full_name: str
    url: str
    status: HealthStatus  # healthy, warning, critical, unknown
    score: float  # 0-100
    language: Language
    latest_build: BuildStatus
    metrics: RepoMetrics
    vulnerability_report: VulnerabilityReport | None

    @property
    def is_healthy(self) -> bool

    @property
    def needs_attention(self) -> bool

    @property
    def days_since_commit(self) -> int | None
```

### EcosystemSummary

Aggregated ecosystem health summary.

```python
class EcosystemSummary:
    organization: str
    total_repos: int
    healthy_count: int
    warning_count: int
    critical_count: int
    average_score: float
    total_vulnerabilities: int
    repos: list[RepoHealth]

    @property
    def health_percentage(self) -> float
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub personal access token |
| `GH_TOKEN` | Alternative GitHub token |
| `PULSE_GITHUB_TOKEN` | Pulse-specific GitHub token |

## Requirements

- Python 3.9+
- GitHub personal access token with `repo` scope

## Development

```bash
# Clone repository
git clone https://github.com/sebastienrousseau/pulse.git
cd pulse

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check src/ tests/

# Type checking
mypy src/
```

## Integration

Pulse integrates with the ecosystem:

1. **Pipelines**: Use reusable workflows for consistent CI/CD
2. **Devkit**: Pre-commit hooks ensure code quality
3. **Commons**: Shared Rust utilities for ecosystem tools
4. **Codex**: Documentation hub for ecosystem standards

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE).
