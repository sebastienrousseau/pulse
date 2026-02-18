"""Pulse - Ecosystem health monitoring and dashboard.

A comprehensive monitoring solution for tracking repository health,
dependency vulnerabilities, and quality metrics across the ecosystem.
"""

__version__ = "0.0.1"

from pulse.config import PulseConfig
from pulse.models import RepoHealth, SecurityAlert, VulnerabilityReport
from pulse.monitor import EcosystemMonitor

__all__ = [
    "EcosystemMonitor",
    "PulseConfig",
    "RepoHealth",
    "SecurityAlert",
    "VulnerabilityReport",
]
