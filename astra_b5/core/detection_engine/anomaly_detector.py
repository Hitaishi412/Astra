"""
core/detection_engine/anomaly_detector.py
──────────────────────────────────────────
Statistical anomaly detection over log streams.

Uses scikit-learn's Isolation Forest (no deep learning, no GPU, no PyTorch).
Trains on the first ~200 logs of a session as the "baseline" (assumed mostly
benign noise), then flags subsequent logs that deviate significantly.

Features extracted per log:
    - Hour-of-day
    - Source IP entropy
    - Process name length
    - Whether the log is from a network source
    - Numeric fields like bytes_out, port

This is deliberately simple. Real SOC anomaly detection uses dozens of
features over rolling windows; we keep it lightweight so training is fast
on a student's laptop.
"""

from __future__ import annotations

import math
from collections import deque
from typing import Optional

import numpy as np

from core.log_engine.schemas import LogEntry


# Lazy import so the project still works if scikit-learn isn't installed
# at the time of import (it'll fail at fit time instead).
try:
    from sklearn.ensemble import IsolationForest
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


# ─── Feature extraction ─────────────────────────────────────────────────────
def _shannon_entropy(s: Optional[str]) -> float:
    if not s:
        return 0.0
    freqs: dict[str, int] = {}
    for c in s:
        freqs[c] = freqs.get(c, 0) + 1
    total = len(s)
    return -sum((f / total) * math.log2(f / total) for f in freqs.values())


def _extract_features(log: LogEntry) -> list[float]:
    """Convert a LogEntry into a fixed-length feature vector."""
    return [
        # Time
        float(log.timestamp.hour),
        float(log.timestamp.minute),
        # Network
        _shannon_entropy(log.source_ip) if log.source_ip else 0.0,
        _shannon_entropy(log.destination_ip) if log.destination_ip else 0.0,
        float(log.source_port or 0),
        float(log.destination_port or 0),
        # Process
        float(len(log.process_name or "")),
        float(len(log.command_line or "")),
        _shannon_entropy(log.command_line) if log.command_line else 0.0,
        # Source type (one-hot-ish)
        1.0 if log.source == "windows_event" else 0.0,
        1.0 if log.source == "linux_syslog" else 0.0,
        1.0 if log.source == "network_flow" else 0.0,
        1.0 if log.source == "endpoint_edr" else 0.0,
        # Generic
        float(log.event_id or 0),
        float(_severity_to_num(log.severity)),
        # Raw_data hints (presence indicators)
        1.0 if "bytes_out" in log.raw_data else 0.0,
        float(log.raw_data.get("bytes_out", 0)) if isinstance(log.raw_data.get("bytes_out"), (int, float)) else 0.0,
    ]


def _severity_to_num(severity: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)


# ─── Detector ────────────────────────────────────────────────────────────────
class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector.

    Lifecycle:
        1. Create with default contamination/baseline_size
        2. Buffer the first N logs (`add_for_baseline`)
        3. Once buffer is full, call `fit_baseline()`
        4. Then call `score(log)` for every subsequent log

    If scikit-learn isn't available or fit hasn't happened, score() returns 0.0
    (i.e., not anomalous) so the pipeline keeps running.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        baseline_size: int = 200,
        anomaly_threshold: float = -0.10,
    ):
        self.contamination = contamination
        self.baseline_size = baseline_size
        self.anomaly_threshold = anomaly_threshold

        self._baseline_buffer: deque[LogEntry] = deque(maxlen=baseline_size)
        self._model: Optional[IsolationForest] = None
        self._fitted = False

    # ── Baseline collection ──────────────────────────────────────────────────
    def add_for_baseline(self, log: LogEntry) -> bool:
        """
        Add a log to the baseline buffer.
        Returns True when buffer is full and ready for fit_baseline().
        """
        if self._fitted:
            return True
        self._baseline_buffer.append(log)
        return len(self._baseline_buffer) >= self.baseline_size

    def fit_baseline(self) -> bool:
        """
        Train the Isolation Forest on the buffered baseline logs.
        Returns True on success, False if not enough data or sklearn missing.
        """
        if not _SKLEARN_AVAILABLE:
            print("[ANOMALY] scikit-learn not available — skipping baseline fit.")
            return False

        if len(self._baseline_buffer) < 20:
            return False

        X = np.array([_extract_features(log) for log in self._baseline_buffer])

        self._model = IsolationForest(
            contamination=self.contamination,
            n_estimators=50,
            random_state=42,
            n_jobs=1,
        )
        self._model.fit(X)
        self._fitted = True
        return True

    # ── Scoring ──────────────────────────────────────────────────────────────
    def score(self, log: LogEntry) -> float:
        """
        Return the anomaly score for a single log.

        Returns: float — lower = more anomalous (Isolation Forest convention).
                 0.0 if the model isn't fitted (fail-open).
        """
        if not self._fitted or self._model is None:
            return 0.0
        X = np.array([_extract_features(log)])
        # decision_function: higher = more normal, lower = more anomalous
        score = float(self._model.decision_function(X)[0])
        return score

    def is_anomalous(self, log: LogEntry) -> bool:
        """Convenience: returns True if score is below the configured threshold."""
        if not self._fitted:
            return False
        return self.score(log) < self.anomaly_threshold

    # ── Status ───────────────────────────────────────────────────────────────
    @property
    def is_fitted(self) -> bool:
        return self._fitted

    @property
    def baseline_progress(self) -> float:
        """0.0 to 1.0 — how full the baseline buffer is."""
        return min(1.0, len(self._baseline_buffer) / self.baseline_size)

    def explain(self, log: LogEntry) -> str:
        """Build a human-readable summary of why this log might be anomalous."""
        if not self._fitted:
            return "Anomaly model not yet trained."

        bits = []
        if log.source_port and log.source_port > 49152:
            bits.append(f"high source port {log.source_port}")
        if log.destination_port in (4444, 31337, 6666):
            bits.append(f"suspicious destination port {log.destination_port}")
        if log.command_line and len(log.command_line) > 200:
            bits.append(f"unusually long command line ({len(log.command_line)} chars)")
        if log.command_line and _shannon_entropy(log.command_line) > 4.5:
            bits.append("high-entropy command line (possible obfuscation)")
        if log.raw_data.get("bytes_out", 0) > 10_000_000:
            bits.append(f"large outbound transfer ({log.raw_data['bytes_out']} bytes)")

        if not bits:
            return "Unusual feature combination compared to baseline behavior."
        return "Detected: " + "; ".join(bits) + "."
