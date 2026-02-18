"""Pulse - Ecosystem health monitoring and dashboard.

A comprehensive monitoring solution for tracking repository health,
dependency vulnerabilities, and quality metrics across the ecosystem.
"""

__version__ = "0.0.1"

from pulse.alerting import AlertEvent, AlertManager, SlackChannel
from pulse.cache import MemoryCache, ResponseCache
from pulse.config import PulseConfig
from pulse.models import (
    EcosystemSummary,
    HealthStatus,
    RepoHealth,
    SecurityAlert,
    VulnerabilityReport,
)
from pulse.monitor import EcosystemMonitor
from pulse.reporters import ReportFactory, generate_all_reports
from pulse.trends import TrendAnalyzer, TrendStore

__all__ = [
    # Core
    "EcosystemMonitor",
    "PulseConfig",
    # Models
    "EcosystemSummary",
    "HealthStatus",
    "RepoHealth",
    "SecurityAlert",
    "VulnerabilityReport",
    # Alerting
    "AlertEvent",
    "AlertManager",
    "SlackChannel",
    # Caching
    "MemoryCache",
    "ResponseCache",
    # Reporting
    "ReportFactory",
    "generate_all_reports",
    # Trends
    "TrendAnalyzer",
    "TrendStore",
]
