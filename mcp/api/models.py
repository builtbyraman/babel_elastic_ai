from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Boolean, JSON, ForeignKey
from db import Base


class Tenant(Base):
    __tablename__ = 'tenants'

    id = Column(String(36), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    owner_email = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ApiKey(Base):
    __tablename__ = 'api_keys'

    id = Column(String(36), primary_key=True, index=True)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    # First 8 chars of the raw key — stored plaintext for O(1) lookup
    key_prefix = Column(String(8), nullable=False, unique=True, index=True)
    hashed_key = Column(Text, nullable=False)
    scopes = Column(JSON, nullable=False, default=list)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = 'audit_logs'

    id = Column(String(36), primary_key=True, index=True)
    tenant_id = Column(String(36), nullable=True, index=True)
    actor = Column(String(128), nullable=True)
    action = Column(String(64), nullable=False)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(36), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Job(Base):
    __tablename__ = 'jobs'

    id = Column(String(36), primary_key=True, index=True)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='SET NULL'), nullable=True, index=True)
    type = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default='PENDING')
    celery_id = Column(String(64), nullable=True, unique=True)
    payload = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Connector(Base):
    __tablename__ = 'connectors'

    id = Column(String(36), primary_key=True, index=True)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True)
    name = Column(String(128), nullable=False)
    type = Column(String(64), nullable=False)
    endpoint = Column(String(256), nullable=False)
    auth_type = Column(String(64), nullable=False)
    credentials_ref = Column(String(256), nullable=True)
    verified = Column(Boolean, default=False, nullable=False)
    last_checked = Column(DateTime, nullable=True)
    metadata_data = Column('metadata', JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Secret(Base):
    __tablename__ = 'secrets'

    id = Column(String(36), primary_key=True, index=True)
    tenant_id = Column(String(36), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True)
    name = Column(String(128), nullable=False, index=True)
    type = Column(String(64), nullable=False)
    # AES-GCM encrypted JSON blob — use crypto.encrypt / crypto.decrypt
    encrypted_value = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
