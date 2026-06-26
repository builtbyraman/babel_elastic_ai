"""
API key authentication for the MCP API.

Key format (shown to user once at creation):  {prefix}.{secret}
  - prefix: first 8 chars of a random 43-char base64url token
  - secret: the full 43-char token
  Storage: prefix stored plaintext (O(1) lookup), bcrypt(secret) stored as hashed_key.

Lookup path: Bearer header → split on '.' → find ApiKey by prefix → bcrypt.verify
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from db import SessionLocal
from models import ApiKey, Tenant

logger = logging.getLogger(__name__)

_pwd_ctx = CryptContext(schemes=['bcrypt'], deprecated='auto')
_bearer = HTTPBearer(auto_error=False)

# Routes that skip auth (checked by prefix match)
_PUBLIC_PREFIXES = ('/health', '/metrics', '/docs', '/openapi')


def hash_key(raw_key: str) -> str:
    return _pwd_ctx.hash(raw_key)


def verify_key(raw_key: str, hashed: str) -> bool:
    return _pwd_ctx.verify(raw_key, hashed)


def get_db():
    with SessionLocal() as session:
        yield session


def get_current_tenant(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    session: Session = Depends(get_db),
) -> Tenant:
    """
    FastAPI dependency — resolves the caller's Tenant from their Bearer API key.
    Raises 401 if missing/invalid, 403 if key is expired.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Missing Authorization header (Bearer <api_key>)',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    token = credentials.credentials
    if '.' not in token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Malformed API key')

    prefix = token[:8]
    api_key_row = session.query(ApiKey).filter(ApiKey.key_prefix == prefix).first()
    if not api_key_row or not verify_key(token, api_key_row.hashed_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid API key')

    if api_key_row.expires_at and api_key_row.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='API key has expired')

    tenant = session.query(Tenant).filter(Tenant.id == api_key_row.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Tenant not found')

    return tenant
