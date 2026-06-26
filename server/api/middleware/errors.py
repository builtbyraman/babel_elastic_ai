"""
RFC 7807 error handling for consistent API error responses.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
import logging
from typing import Any

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Base exception for API errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        error_type: str = "about:blank",
        instance: str = None,
    ):
        self.message = message
        self.status_code = status_code
        self.error_type = error_type
        self.instance = instance


class InvalidRuleError(APIError):
    """Raised when a Sigma rule is invalid."""

    def __init__(self, message: str, instance: str = None):
        super().__init__(
            message=message,
            status_code=400,
            error_type="https://api.sigma-ui.local/errors#invalid-rule",
            instance=instance,
        )


class UnsupportedFormatError(APIError):
    """Raised when an unsupported format is requested."""

    def __init__(self, format: str, instance: str = None):
        super().__init__(
            message=f"Unsupported format: {format}",
            status_code=400,
            error_type="https://api.sigma-ui.local/errors#unsupported-format",
            instance=instance,
        )


class ElasticsearchError(APIError):
    """Raised when Elasticsearch operation fails."""

    def __init__(self, message: str, instance: str = None):
        super().__init__(
            message=message,
            status_code=503,
            error_type="https://api.sigma-ui.local/errors#elasticsearch-error",
            instance=instance,
        )


class ConversionTimeoutError(APIError):
    """Raised when conversion exceeds timeout."""

    def __init__(self, timeout_seconds: int, instance: str = None):
        super().__init__(
            message=f"Conversion timed out after {timeout_seconds} seconds",
            status_code=408,
            error_type="https://api.sigma-ui.local/errors#timeout",
            instance=instance,
        )


def setup_exception_handlers(app: FastAPI):
    """Setup exception handlers for the FastAPI app."""

    @app.exception_handler(APIError)
    async def api_error_handler(request: Request, exc: APIError):
        """Handle custom API errors with RFC 7807 format."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "type": exc.error_type,
                "status": exc.status_code,
                "title": exc.error_type.split("#")[-1] if "#" in exc.error_type else "Error",
                "detail": exc.message,
                "instance": exc.instance or str(request.url),
            },
        )

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError):
        """Handle Pydantic validation errors."""
        errors = exc.errors()
        return JSONResponse(
            status_code=422,
            content={
                "type": "https://api.sigma-ui.local/errors#validation-error",
                "status": 422,
                "title": "Validation Error",
                "detail": "Invalid request body",
                "instance": str(request.url),
                "errors": [
                    {
                        "field": ".".join(str(loc) for loc in err["loc"]),
                        "message": err["msg"],
                    }
                    for err in errors
                ],
            },
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception):
        """Handle unexpected errors."""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "type": "https://api.sigma-ui.local/errors#internal-error",
                "status": 500,
                "title": "Internal Server Error",
                "detail": "An unexpected error occurred",
                "instance": str(request.url),
            },
        )
