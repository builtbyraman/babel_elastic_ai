import logging
import os
import secrets

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://postgres:postgres@postgres:5432/mcpdb',
)

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def run_migrations() -> None:
    """Run Alembic migrations to head on startup."""
    ini = os.path.join(os.path.dirname(__file__), 'alembic.ini')
    cfg = AlembicConfig(ini)
    cfg.set_main_option('sqlalchemy.url', DATABASE_URL)
    command.upgrade(cfg, 'head')
    logger.info('Database migrations applied.')


def seed_bootstrap() -> None:
    """
    Create the seed tenant + API key from env vars on first startup.

    BOOTSTRAP_TENANT — name for the seed tenant (e.g. 'default')
    BOOTSTRAP_API_KEY — full raw API key to register (optional; one is generated if absent)

    Idempotent: does nothing if a tenant named BOOTSTRAP_TENANT already exists.
    """
    tenant_name = os.getenv('BOOTSTRAP_TENANT', '')
    if not tenant_name:
        return

    from crud import create_tenant, create_api_key, get_tenant_by_name

    with SessionLocal() as session:
        existing = get_tenant_by_name(session, tenant_name)
        if existing:
            logger.info(f"Bootstrap tenant '{tenant_name}' already exists — skipping seed.")
            return

        tenant = create_tenant(session, name=tenant_name, owner_email=os.getenv('BOOTSTRAP_EMAIL', ''))

        raw_key = os.getenv('BOOTSTRAP_API_KEY', '')
        _, issued_key = create_api_key(
            session,
            tenant_id=tenant.id,
            name='bootstrap',
            scopes=['*'],
            raw_key=raw_key or None,
        )

        logger.info(
            f"Bootstrap tenant '{tenant_name}' created (id={tenant.id}). "
            f"API key: {issued_key}  ← store this, it will not be shown again."
        )
