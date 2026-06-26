"""
Health check routes.
"""

from fastapi import APIRouter, Depends
from elasticsearch import Elasticsearch
from config import get_settings, Settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("")
async def health():
    """Health status endpoint."""
    return {"status": "healthy", "service": "sigma-ui-api"}


@router.get("/ready")
async def readiness(settings: Settings = Depends(get_settings)):
    """
    Readiness probe - checks Elasticsearch connectivity.
    Returns 200 if ready, 503 if not.
    """
    try:
        from config import make_es_client
        client = make_es_client(settings)
        health_info = client.cluster.health()
        client.close()

        if health_info.get("status") in ["green", "yellow"]:
            return {
                "status": "ready",
                "elasticsearch": "connected",
                "cluster_health": health_info.get("status"),
            }
        else:
            return {
                "status": "not_ready",
                "elasticsearch": "unhealthy",
                "cluster_health": health_info.get("status"),
            }, 503
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return {"status": "not_ready", "elasticsearch": "unavailable", "error": str(e)}, 503
