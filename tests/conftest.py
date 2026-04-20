"""
Shared test fixtures and configuration.
"""

from __future__ import annotations

import pytest

from src.config import AnomalyConfig, DetectionConfig, RateLimitConfig
from src.engine.anomaly_detector import AnomalyDetector
from src.engine.decision_engine import DecisionEngine
from src.engine.detector import DetectionEngine
from src.engine.feature_extractor import FeatureExtractor
from src.engine.rate_limiter import SlidingWindowRateLimiter
from src.rules.signatures import SignatureEngine


@pytest.fixture
def signature_engine() -> SignatureEngine:
    """Create a signature engine with default rules."""
    return SignatureEngine()


@pytest.fixture
def rate_limiter() -> SlidingWindowRateLimiter:
    """Create a rate limiter with strict settings for testing."""
    config = RateLimitConfig(
        max_requests=5,
        window_seconds=60,
    )
    return SlidingWindowRateLimiter(config)


@pytest.fixture
def anomaly_detector() -> AnomalyDetector:
    """Create an anomaly detector with default config."""
    return AnomalyDetector()


@pytest.fixture
def feature_extractor() -> FeatureExtractor:
    """Create a feature extractor."""
    return FeatureExtractor()


@pytest.fixture
def decision_engine() -> DecisionEngine:
    """Create a decision engine."""
    return DecisionEngine(multiple_anomaly_threshold=3)


@pytest.fixture
def detection_engine() -> DetectionEngine:
    """Create a detection engine with test configuration."""
    config = DetectionConfig(
        rate_limit=RateLimitConfig(
            max_requests=5,
            window_seconds=60,
        ),
        anomaly=AnomalyConfig(
            sigma_threshold=3.0,
            multiple_anomaly_threshold=3,
        ),
    )
    return DetectionEngine(config)


@pytest.fixture
def legit_request() -> dict:
    """Sample legitimate request."""
    return {
        "method": "GET",
        "url": "/api/v1/users?page=1&limit=10",
        "headers": {
            "content-type": "application/json",
            "accept": "application/json",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        },
        "body": "",
        "ip_address": "192.168.1.100",
    }


@pytest.fixture
def sqli_request() -> dict:
    """Sample SQL injection request."""
    return {
        "method": "POST",
        "url": "/api/v1/users",
        "headers": {
            "content-type": "application/json",
        },
        "body": '{"username": "admin\' OR 1=1 --", "password": "test"}',
        "ip_address": "10.0.0.1",
    }


@pytest.fixture
def xss_request() -> dict:
    """Sample XSS request."""
    return {
        "method": "POST",
        "url": "/api/v1/comments",
        "headers": {
            "content-type": "application/json",
        },
        "body": '{"comment": "<script>alert(document.cookie)</script>"}',
        "ip_address": "10.0.0.2",
    }


@pytest.fixture
def path_traversal_request() -> dict:
    """Sample path traversal request."""
    return {
        "method": "GET",
        "url": "/api/v1/files?path=../../../etc/passwd",
        "headers": {
            "accept": "application/json",
        },
        "body": "",
        "ip_address": "10.0.0.3",
    }


@pytest.fixture
def cmdi_request() -> dict:
    """Sample command injection request."""
    return {
        "method": "POST",
        "url": "/api/v1/ping",
        "headers": {
            "content-type": "application/json",
        },
        "body": '{"host": "127.0.0.1; cat /etc/passwd"}',
        "ip_address": "10.0.0.4",
    }
