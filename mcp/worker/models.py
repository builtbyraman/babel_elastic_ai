from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, JSON, ForeignKey
from db import Base


class Job(Base):
    """Minimal Job model for the worker — only needs status updates."""
    __tablename__ = 'jobs'

    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), nullable=True)
    type = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default='PENDING')
    celery_id = Column(String(64), nullable=True, unique=True)
    payload = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
