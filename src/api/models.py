"""
Pydantic models for API request/response validation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class DetectionRequest(BaseModel):
    """
    Request model for the detection endpoint.
    
    Represents an HTTP request to be analyzed for security threats.
    """
    method: str = Field(
        default="GET",
        description="HTTP method (GET, POST, PUT, DELETE, etc.)",
        pattern=r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$",
    )
    url: str = Field(
        ...,
        description="Request URL path including query string",
        min_length=1,
        max_length=8192,
    )
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="HTTP headers as key-value pairs",
    )
    body: str = Field(
        default="",
        description="Request body as string",
        max_length=1048576,  # 1MB max
    )
    ip_address: str = Field(
        ...,
        description="Client IP address",
        pattern=r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
    )
    
    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, v: str) -> str:
        """Normalize HTTP method to uppercase."""
        return v.upper() if isinstance(v, str) else v
    
    @field_validator("headers")
    @classmethod
    def normalize_headers(cls, v: Dict[str, str]) -> Dict[str, str]:
        """Normalize header keys to lowercase."""
        return {k.lower(): v for k, v in v.items()}


class MatchedRuleInfo(BaseModel):
    """Information about a matched signature rule."""
    rule_id: str
    rule_name: str
    severity: str
    attack_type: str
    matched_field: str
    matched_value: str
    position: int
    description: str


class AnomalyScoreInfo(BaseModel):
    """Anomaly score for a single feature."""
    feature_name: str
    value: float
    mean: float
    std: float
    z_score: float
    is_anomaly: bool
    threshold: float


class AnomalyScoresInfo(BaseModel):
    """Complete anomaly detection results."""
    scores: Dict[str, AnomalyScoreInfo]
    anomaly_count: int
    is_anomalous: bool
    max_z_score: float


class RateLimitStatusInfo(BaseModel):
    """Rate limiting status information."""
    allowed: bool
    current_count: int
    remaining: int
    reset_at: float
    limit: int


class DetectionResponse(BaseModel):
    """
    Response model for the detection endpoint.
    
    Contains the complete analysis result including all
    intermediate detection data.
    """
    is_threat: bool = Field(
        description="Whether the request is considered a threat"
    )
    threat_level: str = Field(
        description="Threat severity: SAFE, LOW, MEDIUM, HIGH, CRITICAL"
    )
    recommendation: str = Field(
        description="Recommended action: ALLOW, FLAG, BLOCK"
    )
    matched_rules: List[MatchedRuleInfo] = Field(
        default_factory=list,
        description="List of signature rules that matched"
    )
    rate_limit_status: RateLimitStatusInfo = Field(
        description="Rate limiting check result"
    )
    anomaly_scores: AnomalyScoresInfo = Field(
        description="Statistical anomaly detection results"
    )
    features: Dict[str, float] = Field(
        default_factory=dict,
        description="Extracted request features"
    )
    reason: str = Field(
        description="Human-readable explanation of the decision"
    )
    triggering_factor: str = Field(
        description="What triggered the decision"
    )


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(description="Service status")
    version: str = Field(description="API version")
    components: Dict[str, str] = Field(
        description="Status of individual components"
    )


class MetricsResponse(BaseModel):
    """Lightweight metrics response."""
    metrics: Dict[str, int] = Field(
        description="Aggregated detection engine metrics"
    )
