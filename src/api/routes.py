"""
API routes for the detection service.
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, HTTPException

from src.api.models import (
    DetectionRequest,
    DetectionResponse,
    HealthResponse,
    MetricsResponse,
)
from src.engine.detector import DetectionEngine

logger = logging.getLogger(__name__)

# Global engine instance (initialized in app.py)
_engine: DetectionEngine = None  # type: ignore


def set_engine(engine: DetectionEngine) -> None:
    """Set the global detection engine instance."""
    global _engine
    _engine = engine


def get_engine() -> DetectionEngine:
    """Get the global detection engine instance."""
    if _engine is None:
        raise RuntimeError("Detection engine not initialized")
    return _engine


router = APIRouter(tags=["detection"])


@router.post(
    "/detect",
    response_model=DetectionResponse,
    summary="Analyze request for threats",
    description="Analyze an HTTP request through the detection pipeline and return threat assessment.",
    responses={
        200: {"description": "Analysis complete"},
        422: {"description": "Invalid request format"},
        500: {"description": "Internal error during analysis"},
    },
)
async def detect_threats(request: DetectionRequest) -> DetectionResponse:
    """
    Analyze a request for security threats.
    
    The request is passed through:
    1. Signature pattern matching
    2. Rate limit checking
    3. Feature extraction
    4. Statistical anomaly detection
    5. Decision engine
    
    Returns comprehensive analysis results.
    """
    try:
        engine = get_engine()
        result = engine.analyze(
            method=request.method,
            url=request.url,
            headers=request.headers,
            body=request.body,
            ip_address=request.ip_address,
        )
        
        # Convert to response model
        return DetectionResponse(
            is_threat=result.is_threat,
            threat_level=result.threat_level.value,
            recommendation=result.recommendation.value,
            matched_rules=result.matched_rules,
            rate_limit_status=result.rate_limit_status,
            anomaly_scores=result.anomaly_scores,
            features=result.features,
            reason=result.reason,
            triggering_factor=result.triggering_factor,
        )
        
    except Exception:
        logger.exception("Error during threat detection")
        raise HTTPException(
            status_code=500,
            detail="Internal error during analysis"
        )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check the health status of the detection service and its components.",
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.
    
    Returns service status and component health.
    """
    components: Dict[str, str] = {
        "signature_engine": "healthy",
        "rate_limiter": "healthy",
        "anomaly_detector": "healthy",
        "decision_engine": "healthy",
    }
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        components=components,
    )


@router.get(
    "/metrics",
    response_model=MetricsResponse,
    summary="Get detection engine metrics",
    description="Return lightweight counters for decision counts and detection events.",
)
async def get_metrics() -> MetricsResponse:
    engine = get_engine()
    return MetricsResponse(metrics=engine.metrics.snapshot())
