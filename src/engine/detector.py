"""
Detection Engine - Main orchestrator.

Coordinates all detection components and produces
the final analysis result.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.config import (
    AnomalyConfig,
    Decision,
    DetectionConfig,
    RateLimitConfig,
    ThreatLevel,
)
from src.engine.anomaly_detector import AnomalyDetector, AnomalyReport
from src.engine.decision_engine import DecisionEngine, DecisionResult
from src.engine.feature_extractor import FeatureExtractor, RequestFeatures
from src.engine.metrics import metrics, MetricsCollector
from src.engine.rate_limiter import RateLimitResult, SlidingWindowRateLimiter
from src.rules.models import RuleMatch
from src.rules.signatures import SignatureEngine

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """
    Complete detection result for a request.
    
    This is the main output of the DetectionEngine and contains
    all information needed for response and logging.
    """
    is_threat: bool
    threat_level: ThreatLevel
    recommendation: Decision
    matched_rules: List[Dict]
    rate_limit_status: Dict
    anomaly_scores: Dict
    features: Dict
    reason: str
    triggering_factor: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "is_threat": self.is_threat,
            "threat_level": self.threat_level.value,
            "recommendation": self.recommendation.value,
            "matched_rules": self.matched_rules,
            "rate_limit_status": self.rate_limit_status,
            "anomaly_scores": self.anomaly_scores,
            "features": self.features,
            "reason": self.reason,
            "triggering_factor": self.triggering_factor,
        }


class DetectionEngine:
    """
    Main detection engine orchestrator.
    
    Pipeline:
    1. Pattern Matching (Signature Rules)
    2. Rate Limiting (Sliding Window)
    3. Feature Extraction
    4. Anomaly Detection (3-sigma)
    5. Decision Engine
    
    Usage:
        engine = DetectionEngine()
        result = engine.analyze(
            method="POST",
            url="/api/users",
            headers={"Content-Type": "application/json"},
            body='{"name": "test"}',
            ip_address="192.168.1.1"
        )
    """
    
    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        """
        Initialize the detection engine.
        
        Args:
            config: Optional configuration override
        """
        self._config = config or DetectionConfig()
        
        # Initialize components
        self._signature_engine = SignatureEngine()
        self._rate_limiter = SlidingWindowRateLimiter(self._config.rate_limit)
        self._anomaly_detector = AnomalyDetector(self._config.anomaly)
        self._decision_engine = DecisionEngine(
            multiple_anomaly_threshold=self._config.anomaly.multiple_anomaly_threshold
        )
        self._feature_extractor = FeatureExtractor()
        self._metrics = metrics
    
    @property
    def signature_engine(self) -> SignatureEngine:
        """Access the signature engine for rule management."""
        return self._signature_engine
    
    @property
    def rate_limiter(self) -> SlidingWindowRateLimiter:
        """Access the rate limiter for management."""
        return self._rate_limiter
    
    @property
    def anomaly_detector(self) -> AnomalyDetector:
        """Access the anomaly detector for baseline management."""
        return self._anomaly_detector

    @property
    def metrics(self) -> MetricsCollector:
        """Access the internal metrics collector."""
        return self._metrics
    
    def _format_matched_rules(self, matches: List[RuleMatch]) -> List[Dict]:
        """Format rule matches for response."""
        return [
            {
                "rule_id": match.rule.id,
                "rule_name": match.rule.name,
                "severity": match.rule.severity.value,
                "attack_type": match.rule.attack_type.value,
                "matched_field": match.matched_field,
                "matched_value": match.matched_value[:100],  # Truncate long values
                "position": match.position,
                "description": match.rule.description,
            }
            for match in matches
        ]
    
    def analyze(
        self,
        method: str,
        url: str,
        headers: dict,
        body: str,
        ip_address: str,
    ) -> DetectionResult:
        """
        Analyze a request through the full detection pipeline.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL path (including query string)
            headers: Request headers as dict
            body: Request body as string
            ip_address: Client IP address
            
        Returns:
            Complete DetectionResult with all analysis data
        """
        # Normalize inputs
        method = (method or "").upper()
        url = url or ""
        headers = headers or {}
        body = body or ""
        ip_address = ip_address or "unknown"
        
        logger.debug(
            f"Analyzing request: {method} {url} from {ip_address}"
        )
        self._metrics.increment("requests_total")
        
        # Step 1: Pattern Matching
        matched_rules = self._signature_engine.analyze(
            url=url,
            body=body,
            headers=headers,
            excluded_headers=self._config.excluded_headers,
        )
        
        # Step 2: Rate Limiting
        rate_limit_result = self._rate_limiter.check(ip_address)
        
        # Step 3: Feature Extraction
        features = self._feature_extractor.extract(
            url=url,
            body=body,
            headers=headers,
        )
        
        # Step 4: Anomaly Detection
        anomaly_report = self._anomaly_detector.analyze(features)
        
        # Step 5: Decision Engine
        decision_result = self._decision_engine.decide(
            matched_rules=matched_rules,
            rate_limit_result=rate_limit_result,
            anomaly_report=anomaly_report,
        )
        
        # Build final result
        result = DetectionResult(
            is_threat=decision_result.is_threat,
            threat_level=decision_result.threat_level,
            recommendation=decision_result.decision,
            matched_rules=self._format_matched_rules(matched_rules),
            rate_limit_status=rate_limit_result.to_dict(),
            anomaly_scores=anomaly_report.to_dict(),
            features=features.to_dict(),
            reason=decision_result.reason,
            triggering_factor=decision_result.triggering_factor,
        )
        
        logger.info(
            f"Detection complete: {decision_result.decision.value} "
            f"(threat={decision_result.is_threat}, "
            f"rules={len(matched_rules)}, "
            f"anomalies={anomaly_report.anomaly_count})"
        )

        self._metrics.increment("decisions_total")
        self._metrics.increment(f"decision_{decision_result.decision.value.lower()}")
        if matched_rules:
            self._metrics.increment("signature_matches")
        if anomaly_report.is_anomalous:
            self._metrics.increment("anomaly_detections")
        if not rate_limit_result.allowed:
            self._metrics.increment("rate_limit_blocks")

        return result
