"""
Sigma UI HTTP API - Main FastAPI application.

Provides endpoints for:
- Converting Sigma rules to EQL/ES|QL/Lucene
- Testing converted rules against live Elasticsearch data
- Health checks and readiness probes
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from config import get_settings
from routes import conversions, test_runs, health, fields, validation, coverage, effectiveness, schema_drift, rule_registry, ai, ir_readiness
from middleware.errors import setup_exception_handlers
from middleware.auth import setup_auth_middleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(name)s", "message": "%(message)s"}',
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle (startup/shutdown)."""
    logger.info("Starting Sigma UI API")
    yield
    logger.info("Shutting down Sigma UI API")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
        description=settings.api_description,
        debug=settings.debug,
        lifespan=lifespan,
    )

    # Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # TODO: Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Setup exception handlers (RFC 7807)
    setup_exception_handlers(app)

    # Setup auth middleware
    setup_auth_middleware(app)

    # Routes
    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(conversions.router, prefix="/v1", tags=["conversions"])
    app.include_router(test_runs.router, prefix="/v1", tags=["test-runs"])
    app.include_router(fields.router, prefix="/v1", tags=["fields"])
    app.include_router(validation.router, prefix="/v1", tags=["validation"])
    app.include_router(coverage.router, prefix="/v1", tags=["coverage"])
    app.include_router(effectiveness.router, prefix="/v1", tags=["effectiveness"])
    app.include_router(schema_drift.router, prefix="/v1", tags=["schema-drift"])
    app.include_router(rule_registry.router, prefix="/v1", tags=["rule-registry"])
    app.include_router(ai.router, prefix="/v1", tags=["ai"])
    app.include_router(ir_readiness.router, prefix="/v1", tags=["ir-readiness"])

    logger.info(f"API configured. Elasticsearch: {settings.elasticsearch_url()}")
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
