"""
FastAPI application factory.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import get_engine, router, set_engine
from src.config import AppSettings, DetectionConfig
from src.engine.detector import DetectionEngine
from src.api.exceptions import validation_exception_handler


# Conditional import for request logging (only in tests)
try:
    from tests.export_requests import log_request
    REQUEST_LOGGING_ENABLED = True
except ImportError:
    REQUEST_LOGGING_ENABLED = False
    log_request = None


def setup_logging(level: str = "INFO") -> None:
    """Configure logging for the application."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# Middleware to capture requests for testing
async def request_capture_middleware(request: Request, call_next):
    """Middleware to capture HTTP requests during testing."""
    if REQUEST_LOGGING_ENABLED and log_request:
        # Capture request data
        body = await request.body()
        request_data = {
            "method": request.method,
            "url": str(request.url.path) + ("?" + str(request.url.query) if request.url.query else ""),
            "headers": dict(request.headers),
            "body": body.decode("utf-8", errors="ignore") if body else "",
        }
        log_request(request_data)
    
    # Continue processing
    response = await call_next(request)
    return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown."""
    engine = get_engine()
    logging.getLogger(__name__).info(
        "Detection Engine starting up with %d signature rules",
        len(engine.signature_engine.rules),
    )
    yield
    logging.getLogger(__name__).info("Detection Engine shutting down")


def create_app(
    config: Optional[DetectionConfig] = None,
    log_level: str = "INFO",
) -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Args:
        config: Optional detection configuration
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        Configured FastAPI application
    """
    setup_logging(log_level)

    settings = AppSettings.from_env()
    detection_config = config or settings.to_detection_config()
    engine = DetectionEngine(detection_config)
    set_engine(engine)

    app = FastAPI(
        title="API Security Detection Engine",
        description="""
        Real-time API request threat detection system.
        
        ## Features
        
        - **Signature-based detection**: Regex rules for SQLi, XSS, Path Traversal, CMDi
        - **Rate limiting**: Sliding window per-IP protection
        - **Anomaly detection**: Statistical 3-sigma analysis
        - **Decision engine**: Priority-based threat assessment
        
        ## Pipeline
        
        Request → Pattern Matching → Rate Limiting → Feature Extraction → Anomaly Detection → Decision
        """,
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Add request capture middleware (for testing)
    if REQUEST_LOGGING_ENABLED:
        app.middleware("http")(request_capture_middleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.include_router(router, prefix="/api/v1")

    return app


# Create default app instance for `uvicorn src.api.app:app`
app = create_app()