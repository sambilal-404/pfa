"""
Decision Engine - Final verdict determination.

Implements the priority-based decision logic that combines
results from all detection components into a final action.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from src.config import Decision, Severity, ThreatLevel
from src.rules.models import RuleMatch
from src.engine.anomaly_detector import AnomalyReport
from src.engine.rate_limiter import RateLimitResult


@dataclass(frozen=True)
class DecisionResult:
    """
    Complete decision output with rationale.
    
    Attributes:
        decision: Final action (ALLOW/FLAG/BLOCK)
        threat_level: Threat severity classification
        is_threat: Whether the request is considered a threat
        reason: Human-readable explanation of the decision
        triggering_factor: What caused the decision
    """
    decision: Decision
    threat_level: ThreatLevel
    is_threat: bool
    reason: str
    triggering_factor: str


class DecisionEngine:
    """
    Priority-based decision engine.
    
    Decision Priority Chain:
    1. CRITICAL signature match → BLOCK
    2. Rate limit exceeded → BLOCK
    3. HIGH signature match → BLOCK
    4. Multiple anomalies (≥3) → FLAG
    5. MEDIUM signature match → FLAG
    6. Any single anomaly → FLAG
    7. LOW signature match → FLAG (minor signal)
    8. Otherwise → ALLOW
    
    Design Rationale:
    - CRITICAL rules (SQLi, CMDi) warrant immediate blocking
    - Rate limiting prevents abuse regardless of content
    - HIGH rules (XSS, traversal) also warrant blocking
    - Anomalies alone shouldn't block (false positive risk)
    - FLAG allows human review / ML classification
    - Multiple weak signals combine to increase confidence
    
    This strategy aims to reduce false positives from ~70% to ~10%
    by only blocking on high-confidence signals and using FLAG
    for uncertain cases.
    """
    
    def __init__(self, multiple_anomaly_threshold: int = 3) -> None:
        self._multiple_anomaly_threshold = multiple_anomaly_threshold
    
    def decide(
        self,
        matched_rules: List[RuleMatch],
        rate_limit_result: RateLimitResult,
        anomaly_report: "AnomalyReport",
    ) -> DecisionResult:
        """
        Determine the final decision based on all detection results.
        
        Args:
            matched_rules: List of signature rule matches
            rate_limit_result: Rate limiting check result
            anomaly_report: Anomaly detection report
            
        Returns:
            DecisionResult with final verdict and rationale
        """
        # Extract severity counts and build a simple strength score.
        severity_counts: dict[Severity, int] = {}
        severity_score = 0.0
        for match in matched_rules:
            sev = match.rule.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if sev == Severity.CRITICAL:
                severity_score += 5.0
            elif sev == Severity.HIGH:
                severity_score += 3.0
            elif sev == Severity.MEDIUM:
                severity_score += 1.0
            else:
                severity_score += 0.5
        
        # 1. CRITICAL signature match → BLOCK
        if Severity.CRITICAL in severity_counts:
            rules = [m.rule.name for m in matched_rules if m.rule.severity == Severity.CRITICAL]
            return DecisionResult(
                decision=Decision.BLOCK,
                threat_level=ThreatLevel.CRITICAL,
                is_threat=True,
                reason=f"Critical threat detected: {', '.join(rules[:3])}",
                triggering_factor="critical_signature",
            )

        # 2. Rate limit exceeded → BLOCK
        if not rate_limit_result.allowed:
            return DecisionResult(
                decision=Decision.BLOCK,
                threat_level=ThreatLevel.HIGH,
                is_threat=True,
                reason=f"Rate limit exceeded: {rate_limit_result.current_count}/{rate_limit_result.limit} requests",
                triggering_factor="rate_limit",
            )

        # 3. High severity signature match → BLOCK
        if Severity.HIGH in severity_counts and severity_score >= 3.0:
            rules = [m.rule.name for m in matched_rules if m.rule.severity == Severity.HIGH]
            return DecisionResult(
                decision=Decision.BLOCK,
                threat_level=ThreatLevel.HIGH,
                is_threat=True,
                reason=f"High severity threat detected: {', '.join(rules[:3])}",
                triggering_factor="high_signature",
            )

        # 4. Multiple strong anomalies or very high anomaly score → FLAG
        anomaly_confidence = sum(
            min(abs(score.z_score), 6.0)
            for score in anomaly_report.scores.values()
            if score.is_anomaly
        )
        if anomaly_report.anomaly_count >= self._multiple_anomaly_threshold or anomaly_report.max_z_score >= 4.5:
            anomalous_features = [
                name for name, score in anomaly_report.scores.items()
                if score.is_anomaly
            ]
            return DecisionResult(
                decision=Decision.FLAG,
                threat_level=ThreatLevel.MEDIUM,
                is_threat=True,
                reason=f"Anomalous request characteristics detected: {', '.join(anomalous_features[:3])}",
                triggering_factor="anomaly_score",
            )

        # 5. Medium severity signature + any anomaly → FLAG
        if Severity.MEDIUM in severity_counts:
            rules = [m.rule.name for m in matched_rules if m.rule.severity == Severity.MEDIUM]
            if anomaly_report.is_anomalous or severity_counts[Severity.MEDIUM] > 1:
                return DecisionResult(
                    decision=Decision.FLAG,
                    threat_level=ThreatLevel.LOW,
                    is_threat=True,
                    reason=f"Medium severity pattern detected: {', '.join(rules[:3])}",
                    triggering_factor="medium_signature",
                )

        # 6. Any single anomaly with high z-score → FLAG
        if anomaly_report.is_anomalous and anomaly_confidence >= 3.5:
            anomalous_features = [
                name for name, score in anomaly_report.scores.items()
                if score.is_anomaly
            ]
            return DecisionResult(
                decision=Decision.FLAG,
                threat_level=ThreatLevel.LOW,
                is_threat=True,
                reason=f"Statistical anomaly detected: {', '.join(anomalous_features[:3])}",
                triggering_factor="single_anomaly",
            )

        # 7. Low severity signature alone → FLAG
        if Severity.LOW in severity_counts:
            rules = [m.rule.name for m in matched_rules if m.rule.severity == Severity.LOW]
            return DecisionResult(
                decision=Decision.FLAG,
                threat_level=ThreatLevel.LOW,
                is_threat=True,
                reason=f"Low severity pattern detected: {', '.join(rules[:3])}",
                triggering_factor="low_signature",
            )

        # 8. Otherwise → ALLOW
        return DecisionResult(
            decision=Decision.ALLOW,
            threat_level=ThreatLevel.SAFE,
            is_threat=False,
            reason="No threats detected",
            triggering_factor="none",
        )
