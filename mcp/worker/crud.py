from typing import Optional
from sqlalchemy.orm import Session

from models import Job


def get_job(session: Session, job_id: str) -> Optional[Job]:
    return session.query(Job).filter(Job.id == job_id).first()


def update_job_status(
    session: Session,
    job_id: str,
    status: str,
    result: Optional[dict] = None,
    error: Optional[str] = None,
    celery_id: Optional[str] = None,
) -> Optional[Job]:
    job = get_job(session, job_id)
    if not job:
        return None

    job.status = status
    if celery_id is not None:
        job.celery_id = celery_id
    if result is not None:
        job.result = result
    if error is not None:
        job.error = error
    session.commit()
    session.refresh(job)
    return job
