"""
Data models for signature rules.

Defines the structure for detection rules and their match results.
Uses frozen dataclasses for immutability and hashability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from src.config import AttackType, Severity


@dataclass(frozen=True)
class SignatureRule:
    """
    A signature-based detection rule.
    
    Attributes:
        id: Unique identifier for the rule (e.g., "SQLI-001")
        name: Human-readable rule name
        pattern: Compiled regex pattern for matching
        severity: Threat severity when rule matches
        description: Detailed description of what the rule detects
        attack_type: Category of attack this rule targets
        target_fields: Which request fields to inspect (url, body, headers)
    """
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str
    attack_type: AttackType
    target_fields: tuple[str, ...] = ("url", "body", "headers")


@dataclass(frozen=True)
class RuleMatch:
    """
    Result of a signature rule match.
    
    Attributes:
        rule: The rule that matched
        matched_value: The actual string that triggered the match
        matched_field: Which request field contained the match
        position: Character position where match started (-1 if N/A)
    """
    rule: SignatureRule
    matched_value: str
    matched_field: str
    position: int = -1
