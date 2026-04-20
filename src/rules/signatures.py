"""
Signature Engine - Pattern-based threat detection.

Implements regex-based detection for common attack patterns.
All patterns are pre-compiled at module load time for performance.
"""

from __future__ import annotations

import re
from typing import List, Optional

from src.config import AttackType, Severity
from src.rules.models import RuleMatch, SignatureRule
from src.rules.normalization import build_scan_values


def _compile_pattern(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    """Compile a regex pattern with common flags."""
    return re.compile(pattern, flags)


class SignatureEngine:
    """
    Pattern-matching engine using pre-compiled signature rules.
    
    The engine maintains a registry of rules and applies them to
    request fields to identify known attack patterns.
    
    Design Notes:
    - Patterns are compiled once at initialization
    - Rules are ordered by severity for early termination optimization
    - Multiple matches per request are supported
    - Case-insensitive matching by default
    """
    
    def __init__(self, rules: Optional[List[SignatureRule]] = None) -> None:
        """
        Initialize the signature engine.
        
        Args:
            rules: Optional custom rules list. If None, uses default rules.
        """
        self._rules: List[SignatureRule] = rules or self._default_rules()
        # Sort by severity (highest first) for potential early termination
        self._rules.sort(key=lambda r: list(Severity).index(r.severity), reverse=True)
        self._rule_map = {rule.id: rule for rule in self._rules}
    
    @property
    def rules(self) -> List[SignatureRule]:
        """Return a copy of the rules list."""
        return list(self._rules)
    
    def add_rule(self, rule: SignatureRule) -> None:
        """Add a new rule to the engine."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: list(Severity).index(r.severity), reverse=True)
        self._rule_map[rule.id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns True if found and removed."""
        if rule_id in self._rule_map:
            rule = self._rule_map.pop(rule_id)
            self._rules = [r for r in self._rules if r.id != rule_id]
            return True
        return False
    
    def analyze(
        self,
        url: str,
        body: str,
        headers: dict,
        excluded_headers: Optional[List[str]] = None
    ) -> List[RuleMatch]:
        """
        Analyze request fields against all signature rules.
        
        Args:
            url: Request URL path (including query string)
            body: Request body as string
            headers: Request headers as dict
            excluded_headers: Headers to skip during inspection
            
        Returns:
            List of all rule matches found
        """
        excluded = set((excluded_headers or []).copy())
        matches: List[RuleMatch] = []
        seen_matches: set[tuple[str, str]] = set()
        
        # Build field map
        fields_to_check = {
            "url": url,
            "body": body,
        }
        
        # Add non-excluded headers as a combined string
        header_values = [
            f"{k}: {v}" 
            for k, v in headers.items() 
            if k.lower() not in excluded
        ]
        fields_to_check["headers"] = "\n".join(header_values)
        
        for rule in self._rules:
            for field_name in rule.target_fields:
                if field_name not in fields_to_check:
                    continue
                
                field_value = fields_to_check[field_name]
                if not field_value:
                    continue

                for candidate in build_scan_values(field_value):
                    if (rule.id, field_name) in seen_matches:
                        break

                    match = rule.pattern.search(candidate)
                    if not match:
                        continue

                    seen_matches.add((rule.id, field_name))
                    matches.append(RuleMatch(
                        rule=rule,
                        matched_value=match.group(),
                        matched_field=field_name,
                        position=match.start()
                    ))
                    break
        
        return matches
    
    @staticmethod
    def _default_rules() -> List[SignatureRule]:
        """
        Generate default signature rules for common attack patterns.
        
        Rules are designed to balance detection coverage with
        false positive reduction. Each rule targets specific
        attack vectors with appropriate severity levels.
        """
        return [
            # ============ SQL INJECTION RULES ============
            SignatureRule(
                id="SQLI-001",
                name="SQL Union-Based Injection",
                pattern=_compile_pattern(
                    r"(?:UNION\s+(?:ALL\s+)?SELECT)"
                ),
                severity=Severity.CRITICAL,
                description="Detects UNION-based SQL injection attempts",
                attack_type=AttackType.SQL_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="SQLI-002",
                name="SQL Tautology (OR 1=1)",
                pattern=_compile_pattern(
                    r"(?:\bOR\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)|(?:\bOR\b\s+[\'\"]?[a-z]+[\'\"]?\s*=\s*[\'\"]?[a-z]+[\'\"]?)"
                ),
                severity=Severity.CRITICAL,
                description="Detects tautology-based SQL injection (e.g., OR 1=1)",
                attack_type=AttackType.SQL_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="SQLI-003",
                name="SQL Comment-Based Injection",
                pattern=_compile_pattern(
                    r"(?:--\s*$)|(?:/\*.*?\*/)|(?:#\s*$)"
                ),
                severity=Severity.HIGH,
                description="Detects SQL comment sequences used to bypass filters",
                attack_type=AttackType.SQL_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="SQLI-004",
                name="SQL DML Statement",
                pattern=_compile_pattern(
                    r"(?:\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|EXEC)\b)"
                    r"(?=[\s\S]{0,120}(?:FROM|INTO|SET|TABLE|VALUES|WHERE))"
                ),
                severity=Severity.MEDIUM,
                description="Detects SQL keywords only when SQL-like structure is present",
                attack_type=AttackType.SQL_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="SQLI-005",
                name="SQL String Termination",
                pattern=_compile_pattern(
                    r"(?:\'\s*(?:OR|AND|UNION|SELECT)\b)|(?:\'\s*;\s*(?:DROP|DELETE|UPDATE|INSERT))"
                ),
                severity=Severity.CRITICAL,
                description="Detects SQL string termination with subsequent injection",
                attack_type=AttackType.SQL_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="SQLI-006",
                name="SQL Function Injection",
                pattern=_compile_pattern(
                    r"(?:\b(?:SLEEP|BENCHMARK|WAITFOR|DELAY|PG_SLEEP)\s*\()"
                ),
                severity=Severity.HIGH,
                description="Detects time-based blind SQL injection functions",
                attack_type=AttackType.SQL_INJECTION,
                target_fields=("url", "body")
            ),
            
            # ============ XSS RULES ============
            SignatureRule(
                id="XSS-001",
                name="Script Tag Injection",
                pattern=_compile_pattern(
                    r"<\s*script[^>]*>.*?<\s*/\s*script\s*>",
                    re.IGNORECASE | re.DOTALL
                ),
                severity=Severity.CRITICAL,
                description="Detects script tag injection",
                attack_type=AttackType.XSS,
                target_fields=("url", "body", "headers")
            ),
            SignatureRule(
                id="XSS-002",
                name="Event Handler Injection",
                pattern=_compile_pattern(
                    r"<[^>]+on(?:error|load|click|mouseover|focus|blur|submit|change)\s*=\s*['\"]"
                ),
                severity=Severity.HIGH,
                description="Detects HTML event handler injection in tags",
                attack_type=AttackType.XSS,
                target_fields=("url", "body", "headers")
            ),
            SignatureRule(
                id="XSS-003",
                name="JavaScript Protocol",
                pattern=_compile_pattern(
                    r"(?:[\s\"'\(>]|^)javascript\s*:\s*"
                ),
                severity=Severity.HIGH,
                description="Detects javascript: URI scheme in link or script contexts",
                attack_type=AttackType.XSS,
                target_fields=("url", "body", "headers")
            ),
            SignatureRule(
                id="XSS-004",
                name="HTML Entity XSS",
                pattern=_compile_pattern(
                    r"(?:&#x?0*(?:9|10|13|34|39|59|60|62);?)|(?:&#(?:x27|x22|x3c|x3e);)"
                ),
                severity=Severity.MEDIUM,
                description="Detects HTML entity encoding used for XSS evasion",
                attack_type=AttackType.XSS,
                target_fields=("url", "body", "headers")
            ),
            SignatureRule(
                id="XSS-005",
                name="DOM Source Injection",
                pattern=_compile_pattern(
                    r"(?:document\.(?:cookie|location|write|domain))|(?:window\.(?:location|eval|open))"
                ),
                severity=Severity.HIGH,
                description="Detects DOM property access commonly used in XSS",
                attack_type=AttackType.XSS,
                target_fields=("url", "body")
            ),
            
            # ============ PATH TRAVERSAL RULES ============
            SignatureRule(
                id="PT-001",
                name="Directory Traversal (Basic)",
                pattern=_compile_pattern(
                    r"(?:\.\.[\\/])"
                ),
                severity=Severity.HIGH,
                description="Detects basic directory traversal sequences",
                attack_type=AttackType.PATH_TRAVERSAL,
                target_fields=("url",)
            ),
            SignatureRule(
                id="PT-002",
                name="Path Traversal (Encoded)",
                pattern=_compile_pattern(
                    r"(?:%2e%2e[\\/])|(?:\.\.%2f)|(?:%2e%2e%2f)|(?:\.\.%5c)|(?:%2e%2e%5c)",
                    re.IGNORECASE
                ),
                severity=Severity.HIGH,
                description="Detects URL-encoded directory traversal",
                attack_type=AttackType.PATH_TRAVERSAL,
                target_fields=("url",)
            ),
            SignatureRule(
                id="PT-003",
                name="Path Traversal (Double Encoding)",
                pattern=_compile_pattern(
                    r"(?:%252e%252e[\\/])|(?:%252e%252e%252f)",
                    re.IGNORECASE
                ),
                severity=Severity.HIGH,
                description="Detects double URL-encoded directory traversal",
                attack_type=AttackType.PATH_TRAVERSAL,
                target_fields=("url",)
            ),
            SignatureRule(
                id="PT-004",
                name="Sensitive File Access",
                pattern=_compile_pattern(
                    r"(?:(?:/etc/(?:passwd|shadow|hosts))|(?:/proc/self/)|(?:\\windows\\system32))"
                ),
                severity=Severity.CRITICAL,
                description="Detects attempts to access sensitive system files",
                attack_type=AttackType.PATH_TRAVERSAL,
                target_fields=("url",)
            ),
            
            # ============ COMMAND INJECTION RULES ============
            SignatureRule(
                id="CMDI-001",
                name="Unix Command Injection",
                pattern=_compile_pattern(
                    r"(?:;\s*(?:cat|ls|whoami|id|pwd|uname|wget|curl|nc|bash|sh|python|perl|ruby)\b)"
                ),
                severity=Severity.CRITICAL,
                description="Detects Unix command injection via semicolon",
                attack_type=AttackType.COMMAND_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="CMDI-002",
                name="Command Pipe Injection",
                pattern=_compile_pattern(
                    r"(?:\|\s*(?:cat|ls|whoami|id|pwd|uname|wget|curl|nc|bash|sh)\b)"
                ),
                severity=Severity.CRITICAL,
                description="Detects command injection via pipe operator",
                attack_type=AttackType.COMMAND_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="CMDI-003",
                name="Command Substitution",
                pattern=_compile_pattern(
                    r"(?:\$\([^)]+\))|(?:`[^`]+`)"
                ),
                severity=Severity.HIGH,
                description="Detects shell command substitution",
                attack_type=AttackType.COMMAND_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="CMDI-004",
                name="Logical Operator Injection",
                pattern=_compile_pattern(
                    r"(?:&&\s*(?:cat|ls|whoami|id|pwd|rm|wget|curl)\b)|(?:\|\|\s*(?:cat|ls|whoami|id|pwd)\b)"
                ),
                severity=Severity.HIGH,
                description="Detects command injection via logical operators",
                attack_type=AttackType.COMMAND_INJECTION,
                target_fields=("url", "body")
            ),
            SignatureRule(
                id="CMDI-005",
                name="Windows Command Injection",
                pattern=_compile_pattern(
                    r"(?:\b(?:cmd|powershell|cmd\.exe|powershell\.exe)\b)"
                ),
                severity=Severity.HIGH,
                description="Detects Windows command interpreter references",
                attack_type=AttackType.COMMAND_INJECTION,
                target_fields=("url", "body")
            ),
            
            # ============ PROTOCOL ATTACKS ============
            SignatureRule(
                id="PROTO-001",
                name="SSRF Pattern",
                pattern=_compile_pattern(
                    r"(?:(?:https?:)?//(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+))"
                ),
                severity=Severity.HIGH,
                description="Detects Server-Side Request Forgery patterns",
                attack_type=AttackType.PROTOCOL_ATTACK,
                target_fields=("url", "body", "headers")
            ),
            SignatureRule(
                id="PROTO-002",
                name="Log4j JNDI Pattern",
                pattern=_compile_pattern(
                    r"(?:\$\{jndi:(?:ldap|rmi|dns|iiop|nis|nds|corba):)"
                ),
                severity=Severity.CRITICAL,
                description="Detects Log4Shell (CVE-2021-44228) exploitation attempts",
                attack_type=AttackType.PROTOCOL_ATTACK,
                target_fields=("url", "body", "headers")
            ),
        ]
