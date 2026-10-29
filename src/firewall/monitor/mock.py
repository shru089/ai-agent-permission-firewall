"""
Deterministic Mock Monitors for integration testing and verification of fail-closed semantics.
Source: 05_TECHNICAL_SPEC.md §9, 06_EXPERIMENT_PROTOCOL.md §4
"""

from typing import Optional

from firewall.contracts.enums import MonitorVerdict, ScoreKind
from firewall.contracts.models import MonitorAssessment, MonitorView


class DeterministicMockMonitor:
    """
    Configurable deterministic mock monitor for testing.
    Can inject verdicts, scores, exceptions, or timeouts.
    """

    def __init__(
        self,
        monitor_id: str = "mock_monitor",
        version: str = "0.1.0",
        verdict: MonitorVerdict = MonitorVerdict.BENIGN,
        score: Optional[float] = None,
        score_kind: ScoreKind = ScoreKind.NONE,
        rationale: Optional[str] = "Mock evaluation",
        raise_exception: Optional[Exception] = None,
        simulate_timeout: bool = False,
    ) -> None:
        self.monitor_id = monitor_id
        self.version = version
        self.verdict = verdict
        self.score = score
        self.score_kind = score_kind
        self.rationale = rationale
        self.raise_exception = raise_exception
        self.simulate_timeout = simulate_timeout

    def assess(
        self,
        view: MonitorView,
        *,
        timeout_ms: Optional[int] = None,
    ) -> MonitorAssessment:
        if self.simulate_timeout:
            raise TimeoutError("Simulated monitor timeout exceeded")

        if self.raise_exception:
            raise self.raise_exception

        return MonitorAssessment(
            verdict=self.verdict,
            score=self.score,
            score_kind=self.score_kind,
            rationale=self.rationale,
            raw_output=f'{{"verdict": "{self.verdict.value}"}}',
            monitor_version=self.version,
            latency_ms=1.0,
        )
