"""Initial schema with tenants, api_keys, audit_logs; tenant_id on existing tables.

Revision ID: 001
Revises:
Create Date: 2026-05-19
"""
from typing import Union
from alembic import op
import sqlalchemy as sa

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── New tables ────────────────────────────────────────────────────────────
    op.create_table(
        'tenants',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('owner_email', sa.String(256), nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('key_prefix', sa.String(8), nullable=False, unique=True),
        sa.Column('hashed_key', sa.Text, nullable=False),
        sa.Column('scopes', sa.JSON, nullable=False),
        sa.Column('expires_at', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_api_keys_tenant_id', 'api_keys', ['tenant_id'])
    op.create_index('ix_api_keys_key_prefix', 'api_keys', ['key_prefix'], unique=True)

    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('tenant_id', sa.String(36), nullable=True),
        sa.Column('actor', sa.String(128), nullable=True),
        sa.Column('action', sa.String(64), nullable=False),
        sa.Column('resource_type', sa.String(64), nullable=True),
        sa.Column('resource_id', sa.String(36), nullable=True),
        sa.Column('details', sa.JSON, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_audit_logs_tenant_id', 'audit_logs', ['tenant_id'])

    # ── Existing tables — create if not exist, add tenant_id ─────────────────
    # Use try/except per-table to handle both fresh and existing DBs

    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing = inspector.get_table_names()

    if 'jobs' not in existing:
        op.create_table(
            'jobs',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='SET NULL'), nullable=True),
            sa.Column('type', sa.String(32), nullable=False),
            sa.Column('status', sa.String(32), nullable=False),
            sa.Column('celery_id', sa.String(64), nullable=True, unique=True),
            sa.Column('payload', sa.JSON, nullable=True),
            sa.Column('result', sa.JSON, nullable=True),
            sa.Column('error', sa.Text, nullable=True),
            sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
            sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        )
    else:
        cols = {c['name'] for c in inspector.get_columns('jobs')}
        if 'tenant_id' not in cols:
            op.add_column('jobs', sa.Column('tenant_id', sa.String(36), nullable=True))

    if 'connectors' not in existing:
        op.create_table(
            'connectors',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True),
            sa.Column('name', sa.String(128), nullable=False),
            sa.Column('type', sa.String(64), nullable=False),
            sa.Column('endpoint', sa.String(256), nullable=False),
            sa.Column('auth_type', sa.String(64), nullable=False),
            sa.Column('credentials_ref', sa.String(256), nullable=True),
            sa.Column('verified', sa.Boolean, nullable=False, server_default='false'),
            sa.Column('last_checked', sa.DateTime, nullable=True),
            sa.Column('metadata', sa.JSON, nullable=True),
            sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
            sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        )
    else:
        cols = {c['name'] for c in inspector.get_columns('connectors')}
        if 'tenant_id' not in cols:
            op.add_column('connectors', sa.Column('tenant_id', sa.String(36), nullable=True))

    if 'secrets' not in existing:
        op.create_table(
            'secrets',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True),
            sa.Column('name', sa.String(128), nullable=False),
            sa.Column('type', sa.String(64), nullable=False),
            sa.Column('encrypted_value', sa.Text, nullable=False),
            sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
            sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        )
    else:
        cols = {c['name'] for c in inspector.get_columns('secrets')}
        if 'tenant_id' not in cols:
            op.add_column('secrets', sa.Column('tenant_id', sa.String(36), nullable=True))
        if 'encrypted_value' not in cols:
            op.add_column('secrets', sa.Column('encrypted_value', sa.Text, nullable=True))


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('api_keys')
    op.drop_table('tenants')
    # Note: does not revert tenant_id columns on existing tables to keep downgrade safe
