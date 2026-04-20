"""
Metrics collector for the detection engine.

Provides lightweight counters for request volume, decisions, and detection events.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict


@dataclass
class MetricsCollector:
    """Thread-safe metrics collector using in-memory counters."""
    _counters: Counter = field(default_factory=Counter)
    _lock: Lock = field(default_factory=Lock)

    def increment(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[key] += amount

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)


metrics = MetricsCollector()
