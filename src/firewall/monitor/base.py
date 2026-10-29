"""
Monitor interface and safe fault/timeout wrapper (C4) for AI Agent Permission Firewall.
Enforces INV-04: Monitor exceptions, timeouts, and malformed outputs fail-closed to UNKNOWN.
Source: 05_TECHNICAL_SPEC.md §9, 01_THREAT_MODEL.md (INV-04, INV-08)
"""

import time
from typing import Optional, Protocol, runtime_checkable

from firewall.contracts.enums import MonitorVerdict
from firewall.contracts.models import MonitorAssessment, MonitorView


@runtime_checkable
class Monitor(Protocol):
    """
    Protocol for execution monitors (C4).
    Source: 05_TECHNICAL_SPEC.md §9
    """

    monitor_id: str
    version: str

    def assess(
        self,
        view: MonitorView,
        *,
        timeout_ms: Optional[int] = None,
    ) -> MonitorAssessment:
        """
        Assess an action request from its allow-listed MonitorView.
        """
        ...


class SafeMonitorWrapper:
    """
    Robust wrapper around any Monitor implementation.
    Guarantees:
    - Never raises an unhandled exception to FirewallCore (INV-04, 05 §9).
    - Translates exceptions, timeouts, and schema errors into MonitorVerdict.UNKNOWN.
    - Accurately captures latency in milliseconds.
    """

    def __init__(self, monitor: Monitor, default_timeout_ms: Optional[int] = None) -> None:
        self.monitor = monitor
        self.default_timeout_ms = default_timeout_ms

    @property
    def monitor_id(self) -> str:
        return self.monitor.monitor_id

    @property
    def version(self) -> str:
        return self.monitor.version

    def assess(
        self,
        view: MonitorView,
        *,
        timeout_ms: Optional[int] = None,
    ) -> MonitorAssessment:
        effective_timeout = timeout_ms if timeout_ms is not None else self.default_timeout_ms
        start_ns = time.perf_counter_ns()

        try:
            assessment = self.monitor.assess(view, timeout_ms=effective_timeout)
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

            # Ensure latency_ms is accurately recorded if not already set
            if assessment.latency_ms <= 0.0:
                return assessment.model_copy(update={"latency_ms": elapsed_ms})
            return assessment

        except TimeoutError as te:
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            return MonitorAssessment(
                verdict=MonitorVerdict.UNKNOWN,
                monitor_version=self.monitor.version,
                error=f"TIMEOUT: {te}",
                latency_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            return MonitorAssessment(
                verdict=MonitorVerdict.UNKNOWN,
                monitor_version=self.monitor.version,
                error=f"MONITOR_EXCEPTION: {type(e).__name__}: {e}",
                latency_ms=elapsed_ms,
            )
