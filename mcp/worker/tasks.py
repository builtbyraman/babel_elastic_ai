import os
from typing import Dict, Optional

import requests
from celery import Celery
from db import SessionLocal
from crud import update_job_status

BROKER = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
RESULT_BACKEND = os.getenv('RESULT_BACKEND', 'redis://redis:6379/1')
MCP_API_BACKEND = os.getenv('MCP_API_BACKEND', 'http://host.docker.internal:8000/v1')

celery_app = Celery('mcp_worker', broker=BROKER, backend=RESULT_BACKEND)


def _phase1_headers() -> dict:
    api_key = os.getenv('SIGMA_API_KEY', '')
    if api_key:
        return {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    return {'Content-Type': 'application/json'}


@celery_app.task(
    bind=True,
    name='mcp.worker.tasks.convert_rule_task',
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={'max_retries': 3},
)
def convert_rule_task(self, rule_yaml: str, format: str = 'eql', pipeline: str = 'ecs_windows'):
    """Convert a Sigma rule via the Phase 1 API."""
    job_id = self.request.id
    with SessionLocal() as session:
        update_job_status(session, job_id, 'STARTED', celery_id=job_id)
        try:
            resp = requests.post(
                f"{MCP_API_BACKEND}/conversions",
                json={'rule_yaml': rule_yaml, 'format': format, 'pipeline': pipeline},
                headers=_phase1_headers(),
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            update_job_status(session, job_id, 'SUCCESS', result=data)
            return data
        except requests.RequestException as e:
            update_job_status(session, job_id, 'RETRY', error=str(e))
            raise self.retry(exc=e)
        except Exception as e:
            update_job_status(session, job_id, 'FAILURE', error=str(e))
            raise


@celery_app.task(
    bind=True,
    name='mcp.worker.tasks.test_rule_task',
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={'max_retries': 3},
)
def test_rule_task(
    self,
    rule_yaml: str,
    index_pattern: str = '*',
    timeframe_hours: int = 24,
    resolved_auth_headers: Optional[Dict[str, str]] = None,
    connector_endpoint: Optional[str] = None,
    pipeline: str = 'ecs_windows',
    query_format: str = 'eql',
):
    """
    Test a Sigma rule against live Elasticsearch data.

    The API resolves connector credentials before dispatching, so this task
    receives already-resolved auth headers and never touches the secrets table.
    """
    job_id = self.request.id
    with SessionLocal() as session:
        update_job_status(session, job_id, 'STARTED', celery_id=job_id)
        try:
            payload = {
                'rule_yaml': rule_yaml,
                'index_pattern': index_pattern,
                'timeframe_hours': timeframe_hours,
                'pipeline': pipeline,
                'query_format': query_format,
            }

            extra_headers: Dict[str, str] = {}
            if resolved_auth_headers:
                extra_headers.update(resolved_auth_headers)

            resp = requests.post(
                f"{MCP_API_BACKEND}/test-runs",
                json=payload,
                headers={**_phase1_headers(), **extra_headers},
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            update_job_status(session, job_id, 'SUCCESS', result=data)
            return data
        except requests.RequestException as e:
            update_job_status(session, job_id, 'RETRY', error=str(e))
            raise self.retry(exc=e)
        except Exception as e:
            update_job_status(session, job_id, 'FAILURE', error=str(e))
            raise
