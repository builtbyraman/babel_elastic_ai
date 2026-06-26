import logging
import secrets as _secrets
from datetime import datetime, timedelta
from typing import Optional, List, Tuple
from uuid import uuid4

from sqlalchemy.orm import Session

from auth import hash_key
from crypto import encrypt, decrypt
from models import ApiKey, AuditLog, Connector, Job, Secret, Tenant

logger = logging.getLogger(__name__)


# ── Tenant ────────────────────────────────────────────────────────────────────

def create_tenant(session: Session, name: str, owner_email: str = '') -> Tenant:
    tenant = Tenant(id=str(uuid4()), name=name, owner_email=owner_email or None)
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    return tenant


def get_tenant_by_name(session: Session, name: str) -> Optional[Tenant]:
    return session.query(Tenant).filter(Tenant.name == name).first()


def get_tenant(session: Session, tenant_id: str) -> Optional[Tenant]:
    return session.query(Tenant).filter(Tenant.id == tenant_id).first()


# ── API Keys ──────────────────────────────────────────────────────────────────

def create_api_key(
    session: Session,
    tenant_id: str,
    name: str,
    scopes: List[str],
    ttl_days: Optional[int] = None,
    raw_key: Optional[str] = None,
) -> Tuple[ApiKey, str]:
    """
    Create and store an API key for a tenant.
    Returns (ApiKey row, plaintext_key) — plaintext shown once to caller, never again.
    """
    if raw_key:
        # Validate format: must be at least 8 chars
        if len(raw_key) < 8:
            raise ValueError('Provided BOOTSTRAP_API_KEY must be at least 8 characters')
        plaintext = raw_key
    else:
        plaintext = _secrets.token_urlsafe(32)  # 43-char base64url

    prefix = plaintext[:8]
    expires_at = datetime.utcnow() + timedelta(days=ttl_days) if ttl_days else None

    row = ApiKey(
        id=str(uuid4()),
        tenant_id=tenant_id,
        name=name,
        key_prefix=prefix,
        hashed_key=hash_key(plaintext),
        scopes=scopes,
        expires_at=expires_at,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row, plaintext


# ── Jobs ──────────────────────────────────────────────────────────────────────

def create_job(session: Session, job_type: str, payload: dict, tenant_id: Optional[str] = None) -> Job:
    job = Job(
        id=str(uuid4()),
        tenant_id=tenant_id,
        type=job_type,
        status='PENDING',
        payload=payload,
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    return job


def get_job(session: Session, job_id: str, tenant_id: Optional[str] = None) -> Optional[Job]:
    q = session.query(Job).filter(Job.id == job_id)
    if tenant_id:
        q = q.filter(Job.tenant_id == tenant_id)
    return q.first()


def update_job_status(
    session: Session,
    job_id: str,
    status: str,
    result: Optional[dict] = None,
    error: Optional[str] = None,
    celery_id: Optional[str] = None,
) -> Optional[Job]:
    # Worker calls this without tenant context — no tenant filter here
    job = session.query(Job).filter(Job.id == job_id).first()
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


# ── Connectors ────────────────────────────────────────────────────────────────

def create_connector(
    session: Session,
    name: str,
    connector_type: str,
    endpoint: str,
    auth_type: str,
    tenant_id: Optional[str] = None,
    credentials_ref: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> Connector:
    connector = Connector(
        id=str(uuid4()),
        tenant_id=tenant_id,
        name=name,
        type=connector_type,
        endpoint=endpoint,
        auth_type=auth_type,
        credentials_ref=credentials_ref,
        verified=False,
        metadata_data=metadata or {},
    )
    session.add(connector)
    session.commit()
    session.refresh(connector)
    return connector


def list_connectors(session: Session, tenant_id: Optional[str] = None) -> List[Connector]:
    q = session.query(Connector)
    if tenant_id:
        q = q.filter(Connector.tenant_id == tenant_id)
    return q.all()


def get_connector(session: Session, connector_id: str, tenant_id: Optional[str] = None) -> Optional[Connector]:
    q = session.query(Connector).filter(Connector.id == connector_id)
    if tenant_id:
        q = q.filter(Connector.tenant_id == tenant_id)
    return q.first()


def update_connector_status(
    session: Session,
    connector_id: str,
    verified: bool,
    last_checked: Optional[str] = None,
) -> Optional[Connector]:
    connector = session.query(Connector).filter(Connector.id == connector_id).first()
    if not connector:
        return None
    connector.verified = verified
    if last_checked:
        ts = last_checked.rstrip('Z')
        connector.last_checked = datetime.fromisoformat(ts)
    session.commit()
    session.refresh(connector)
    return connector


# ── Secrets ───────────────────────────────────────────────────────────────────

def create_secret(
    session: Session,
    name: str,
    secret_type: str,
    value: dict,
    tenant_id: Optional[str] = None,
) -> Secret:
    secret = Secret(
        id=str(uuid4()),
        tenant_id=tenant_id,
        name=name,
        type=secret_type,
        encrypted_value=encrypt(value),
    )
    session.add(secret)
    session.commit()
    session.refresh(secret)
    return secret


def get_secret(session: Session, name: str, tenant_id: Optional[str] = None) -> Optional[Secret]:
    q = session.query(Secret).filter(Secret.name == name)
    if tenant_id:
        q = q.filter(Secret.tenant_id == tenant_id)
    return q.first()


def get_secret_value(session: Session, name: str, tenant_id: Optional[str] = None) -> Optional[dict]:
    """Return the decrypted secret value dict, or None if not found."""
    secret = get_secret(session, name, tenant_id)
    if not secret:
        return None
    try:
        return decrypt(secret.encrypted_value)
    except Exception as e:
        logger.error(f'Failed to decrypt secret {name}: {e}')
        return None


# ── Audit log ─────────────────────────────────────────────────────────────────

def write_audit_log(
    session: Session,
    action: str,
    tenant_id: Optional[str] = None,
    actor: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    log = AuditLog(
        id=str(uuid4()),
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
    )
    session.add(log)
    session.commit()
