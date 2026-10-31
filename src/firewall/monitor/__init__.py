"""
Execution Monitor Package (C4) for AI Agent Permission Firewall.
Source: 05_TECHNICAL_SPEC.md §9
"""

from firewall.monitor.action_only import ActionOnlyMonitor
from firewall.monitor.base import Monitor, SafeMonitorWrapper
from firewall.monitor.hybrid import HybridMonitor
from firewall.monitor.mock import DeterministicMockMonitor
from firewall.monitor.model_client import (
    DeterministicMockModelClient,
    ModelClient,
    MonitorOutputParseError,
    StrictMonitorOutput,
    normalize_to_unknown_assessment,
    parse_monitor_output,
)
from firewall.monitor.transcript import TranscriptMonitor

__all__ = [
    "Monitor",
    "SafeMonitorWrapper",
    "DeterministicMockMonitor",
    "ModelClient",
    "DeterministicMockModelClient",
    "StrictMonitorOutput",
    "MonitorOutputParseError",
    "parse_monitor_output",
    "normalize_to_unknown_assessment",
    "ActionOnlyMonitor",
    "TranscriptMonitor",
    "HybridMonitor",
]
