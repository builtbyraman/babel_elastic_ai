"""
Authentication middleware for API key validation.
"""

from fastapi import FastAPI, status, Request
from starlette.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)


def setup_auth_middleware(app: FastAPI):
    """Setup authentication middleware on the FastAPI app."""

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        """
        Validate Bearer token from Authorization header.

        Set REQUIRE_AUTH=false to skip auth for internal deployments where
        Kibana is the only caller and network-level isolation is sufficient.
        """
        from config import get_settings
        settings = get_settings()

        # Health checks always bypass auth
        if request.url.path.startswith("/health"):
            return await call_next(request)

        # Auth disabled — internal/dev deployment
        if not settings.require_auth:
            request.state.elastic_api_key = ""
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning(f"Missing or invalid Authorization header from {request.client}")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"status": 401, "detail": "Missing Authorization header. Expected: Authorization: Bearer <api-key>"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        api_key = auth_header.removeprefix("Bearer ")
        request.state.elastic_api_key = api_key
        logger.debug(f"Authenticated request from {request.client}")

        return await call_next(request)
