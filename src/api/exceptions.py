"""
Custom exception handling for the FastAPI application.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Return a generic payload validation error without leaking internals."""
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request payload or headers."},
    )
