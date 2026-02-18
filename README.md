# Pulse

Ecosystem health monitoring and metrics dashboard for the Sebastien Rousseau projects.

## Overview

Pulse provides real-time monitoring, dependency tracking, and quality metrics visualization across all ecosystem repositories.

## Features

- Repository health scoring
- Dependency vulnerability tracking
- Build status aggregation
- Quality metrics dashboard
- Automated alerting

## Installation

```bash
pip install pulse-monitor
```

## Usage

```python
from pulse import EcosystemMonitor

monitor = EcosystemMonitor(org="sebastienrousseau")
monitor.scan_all_repos()
monitor.generate_report()
```

## License

Dual-licensed under MIT and Apache-2.0.
