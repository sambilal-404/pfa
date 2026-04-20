"""
Configuration module for the Detection Engine.

Centralizes all configurable parameters with sensible defaults
derived from industry-standard WAF configurations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

import os


class Severity(str, Enum):
    """Threat severity levels in ascending order of danger."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(str, Enum):
    """Categories of attacks the engine can detect."""
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PROTOCOL_ATTACK = "PROTOCOL_ATTACK"
    UNKNOWN = "UNKNOWN"


class Decision(str, Enum):
    """Final decision outcomes for a request."""
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class ThreatLevel(str, Enum):
    """Threat level classification for response."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class RateLimitConfig:
    """Configuration for the sliding window rate limiter."""
    max_requests: int = 100
    window_seconds: int = 60
    cleanup_interval: int = 300  # Clean up stale entries every 5 minutes


@dataclass(frozen=True)
class AnomalyConfig:
    """Configuration for statistical anomaly detection."""
    sigma_threshold: float = 3.0
    multiple_anomaly_threshold: int = 3  # Number of anomalous features to trigger FLAG
    enable_detection: bool = True
    # Baseline values derived from typical REST API traffic patterns
    # These can be updated with real traffic data
    baselines: Dict[str, Dict[str, float]] = field(default_factory=lambda: {
        "url_length": {"mean": 45.0, "std": 25.0},
        "body_length": {"mean": 120.0, "std": 100.0},
        "query_param_count": {"mean": 2.0, "std": 1.5},
        "special_char_count": {"mean": 8.0, "std": 6.0},
        "entropy": {"mean": 3.2, "std": 0.8},
    })


@dataclass(frozen=True)
class DetectionConfig:
    """Main configuration container for the Detection Engine."""
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    # Fields to inspect for signature matching
    inspect_fields: List[str] = field(default_factory=lambda: [
        "url", "body", "headers"
    ])
    # Fields to exclude from header inspection (common false positives)
    excluded_headers: List[str] = field(default_factory=lambda: [
        "user-agent", "accept", "accept-encoding", "accept-language",
        "connection", "host", "content-type", "content-length"
    ])


class AppSettings:
    """Application settings loaded from environment variables."""

    def __init__(
        self,
        service_name: str = "pfa-detection-engine",
        service_version: str = "1.0.0",
        log_level: str = "INFO",
        rate_limit_max_requests: int = 100,
        rate_limit_window_seconds: int = 60,
        rate_limit_cleanup_interval: int = 300,
        anomaly_sigma_threshold: float = 3.0,
        anomaly_multiple_threshold: int = 3,
        anomaly_enable_detection: bool = True,
    ) -> None:
        self.service_name = service_name
        self.service_version = service_version
        self.log_level = log_level
        self.rate_limit_max_requests = rate_limit_max_requests
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.rate_limit_cleanup_interval = rate_limit_cleanup_interval
        self.anomaly_sigma_threshold = anomaly_sigma_threshold
        self.anomaly_multiple_threshold = anomaly_multiple_threshold
        self.anomaly_enable_detection = anomaly_enable_detection

    @classmethod
    def from_env(cls) -> "AppSettings":
        return cls(
            service_name=os.environ.get("PFA_SERVICE_NAME", "pfa-detection-engine"),
            service_version=os.environ.get("PFA_SERVICE_VERSION", "1.0.0"),
            log_level=os.environ.get("PFA_LOG_LEVEL", "INFO"),
            rate_limit_max_requests=int(os.environ.get("PFA_RATE_LIMIT_MAX_REQUESTS", "100")),
            rate_limit_window_seconds=int(os.environ.get("PFA_RATE_LIMIT_WINDOW_SECONDS", "60")),
            rate_limit_cleanup_interval=int(os.environ.get("PFA_RATE_LIMIT_CLEANUP_INTERVAL", "300")),
            anomaly_sigma_threshold=float(os.environ.get("PFA_ANOMALY_SIGMA_THRESHOLD", "3.0")),
            anomaly_multiple_threshold=int(os.environ.get("PFA_ANOMALY_MULTIPLE_THRESHOLD", "3")),
            anomaly_enable_detection=os.environ.get("PFA_ANOMALY_ENABLE_DETECTION", "true").lower() in ("1", "true", "yes"),
        )

    def to_detection_config(self) -> "DetectionConfig":
        return DetectionConfig(
            rate_limit=RateLimitConfig(
                max_requests=self.rate_limit_max_requests,
                window_seconds=self.rate_limit_window_seconds,
                cleanup_interval=self.rate_limit_cleanup_interval,
            ),
            anomaly=AnomalyConfig(
                sigma_threshold=self.anomaly_sigma_threshold,
                multiple_anomaly_threshold=self.anomaly_multiple_threshold,
                enable_detection=self.anomaly_enable_detection,
            ),
        )