"""Начальная схема сервиса модерации пакетов

Revision ID: 0001
Revises: 
Create Date: 2026-07-31 09:00:27.185470+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = '0001'
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table('license',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('spdx_id', sa.String(length=128), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('allowed', sa.Boolean(), nullable=False),
    sa.Column('url', sa.String(length=1024), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_license')),
    sa.UniqueConstraint('spdx_id', name=op.f('uq_license_spdx_id'))
    )
    op.create_table('package',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('manager', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=512), nullable=False),
    sa.Column('display_name', sa.String(length=512), nullable=False),
    sa.Column('confirmed_license_spdx', sa.String(length=128), nullable=True),
    sa.Column('confirmed_license_version', sa.String(length=128), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.CheckConstraint("manager IN ('pypi', 'npm', 'go', 'nuget')", name=op.f('ck_package_manager_code')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_package')),
    sa.UniqueConstraint('manager', 'name', name='uq_package_manager_name')
    )
    op.create_index('ix_package_name', 'package', ['name'], unique=False)
    op.create_table('package_manager',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=64), nullable=False),
    sa.Column('entry_format', sa.String(length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.CheckConstraint("code IN ('pypi', 'npm', 'go', 'nuget')", name=op.f('ck_package_manager_manager_code')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_package_manager')),
    sa.UniqueConstraint('code', name=op.f('uq_package_manager_code'))
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('subject', sa.String(length=255), nullable=True),
    sa.Column('username', sa.String(length=255), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('full_name', sa.String(length=255), nullable=True),
    sa.Column('roles', sa.JSON(), nullable=False),
    sa.Column('is_service', sa.Boolean(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('gitlab_username', sa.String(length=255), nullable=True),
    sa.Column('gitlab_access_token_enc', sa.Text(), nullable=True),
    sa.Column('gitlab_refresh_token_enc', sa.Text(), nullable=True),
    sa.Column('gitlab_token_expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user')),
    sa.UniqueConstraint('subject', name=op.f('uq_user_subject')),
    sa.UniqueConstraint('username', name=op.f('uq_user_username'))
    )
    op.create_table('vuln_index_version',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('version', sa.String(length=128), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('checksum', sa.String(length=128), nullable=True),
    sa.Column('remote_path', sa.String(length=512), nullable=True),
    sa.Column('local_path', sa.String(length=512), nullable=True),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('downloaded_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('record_count', sa.Integer(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vuln_index_version')),
    sa.UniqueConstraint('version', name=op.f('uq_vuln_index_version_version'))
    )
    op.create_table('audit_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('actor_id', sa.Integer(), nullable=True),
    sa.Column('actor_name', sa.String(length=255), nullable=False),
    sa.Column('actor_role', sa.String(length=32), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('entity_type', sa.String(length=64), nullable=False),
    sa.Column('entity_id', sa.String(length=64), nullable=True),
    sa.Column('old_value', sa.JSON(), nullable=True),
    sa.Column('new_value', sa.JSON(), nullable=True),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('request_id', sa.String(length=64), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['user.id'], name=op.f('fk_audit_log_actor_id_user'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_log'))
    )
    op.create_index('ix_audit_log_created_at', 'audit_log', ['created_at'], unique=False)
    op.create_index('ix_audit_log_entity', 'audit_log', ['entity_type', 'entity_id'], unique=False)
    op.create_table('moderation_request',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('author_id', sa.Integer(), nullable=False),
    sa.Column('author_role', sa.String(length=32), nullable=True),
    sa.Column('manager', sa.String(length=16), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('idempotency_key', sa.String(length=255), nullable=True),
    sa.Column('origin_file', sa.String(length=512), nullable=True),
    sa.Column('include_transitive', sa.Boolean(), nullable=False),
    sa.Column('warnings', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.CheckConstraint("manager IN ('pypi', 'npm', 'go', 'nuget')", name=op.f('ck_moderation_request_manager_code')),
    sa.CheckConstraint("source IN ('api', 'ui', 'cli', 'gitlab')", name=op.f('ck_moderation_request_request_source')),
    sa.CheckConstraint("status IN ('pending', 'awaiting_security', 'awaiting_legal', 'quarantined', 'approved', 'partially_approved', 'rejected', 'failed')", name=op.f('ck_moderation_request_request_status')),
    sa.ForeignKeyConstraint(['author_id'], ['user.id'], name=op.f('fk_moderation_request_author_id_user')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_moderation_request')),
    sa.UniqueConstraint('idempotency_key', name='uq_moderation_request_idempotency_key')
    )
    op.create_index('ix_moderation_request_status', 'moderation_request', ['status'], unique=False)
    op.create_table('package_version',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('package_id', sa.Integer(), nullable=False),
    sa.Column('version', sa.String(length=128), nullable=False),
    sa.Column('raw_version', sa.String(length=128), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('quarantine_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('license_spdx', sa.String(length=128), nullable=True),
    sa.Column('license_source', sa.String(length=32), nullable=True),
    sa.Column('license_raw', sa.Text(), nullable=True),
    sa.Column('registry_metadata', sa.JSON(), nullable=True),
    sa.Column('vuln_index_version_id', sa.Integer(), nullable=True),
    sa.Column('max_vuln_score', sa.Float(), nullable=True),
    sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('status_reason', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.CheckConstraint("status IN ('new', 'checking', 'quarantined', 'awaiting_legal', 'license_claimed', 'awaiting_security', 'approved', 'rejected', 'revoked', 'blacklisted', 'failed')", name=op.f('ck_package_version_version_status')),
    sa.ForeignKeyConstraint(['package_id'], ['package.id'], name=op.f('fk_package_version_package_id_package'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vuln_index_version_id'], ['vuln_index_version.id'], name=op.f('fk_package_version_vuln_index_version_id_vuln_index_version')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_package_version')),
    sa.UniqueConstraint('package_id', 'version', name='uq_package_version_package_id')
    )
    op.create_index('ix_package_version_quarantine_until', 'package_version', ['quarantine_until'], unique=False)
    op.create_index('ix_package_version_status', 'package_version', ['status'], unique=False)
    op.create_table('artifact',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('package_version_id', sa.Integer(), nullable=False),
    sa.Column('filename', sa.String(length=512), nullable=False),
    sa.Column('source_url', sa.String(length=2048), nullable=True),
    sa.Column('size_bytes', sa.Integer(), nullable=True),
    sa.Column('sha256', sa.String(length=128), nullable=True),
    sa.Column('declared_checksum', sa.String(length=160), nullable=True),
    sa.Column('checksum_algo', sa.String(length=16), nullable=True),
    sa.Column('s3_bucket', sa.String(length=128), nullable=True),
    sa.Column('s3_key', sa.String(length=1024), nullable=True),
    sa.Column('s3_uploaded_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('s3_deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('nexus_url', sa.String(length=2048), nullable=True),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.CheckConstraint("status IN ('downloaded', 'scanned', 'published', 'purged', 'failed')", name=op.f('ck_artifact_artifact_status')),
    sa.ForeignKeyConstraint(['package_version_id'], ['package_version.id'], name=op.f('fk_artifact_package_version_id_package_version'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_artifact'))
    )
    op.create_index('ix_artifact_package_version_id', 'artifact', ['package_version_id'], unique=False)
    op.create_table('request_item',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('request_id', sa.Integer(), nullable=False),
    sa.Column('package_version_id', sa.Integer(), nullable=False),
    sa.Column('requested_name', sa.String(length=512), nullable=False),
    sa.Column('requested_version', sa.String(length=128), nullable=False),
    sa.Column('dependency_kind', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('current_step', sa.String(length=32), nullable=True),
    sa.Column('next_action', sa.Text(), nullable=True),
    sa.Column('blocked_reason', sa.Text(), nullable=True),
    sa.Column('waiting_since', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.CheckConstraint("dependency_kind IN ('direct', 'transitive')", name=op.f('ck_request_item_dependency_kind')),
    sa.CheckConstraint("status IN ('queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed', 'awaiting_security', 'approved', 'rejected', 'revoked', 'blacklisted', 'failed')", name=op.f('ck_request_item_item_status')),
    sa.ForeignKeyConstraint(['package_version_id'], ['package_version.id'], name=op.f('fk_request_item_package_version_id_package_version'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['request_id'], ['moderation_request.id'], name=op.f('fk_request_item_request_id_moderation_request'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_request_item'))
    )
    op.create_index('ix_request_item_request_id', 'request_item', ['request_id'], unique=False)
    op.create_index('ix_request_item_status', 'request_item', ['status'], unique=False)
    op.create_table('vulnerability',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('package_version_id', sa.Integer(), nullable=False),
    sa.Column('external_id', sa.String(length=64), nullable=False),
    sa.Column('aliases', sa.JSON(), nullable=True),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('cvss_vector', sa.String(length=256), nullable=True),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.Column('score', sa.Float(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('url', sa.String(length=1024), nullable=True),
    sa.Column('affected_ranges', sa.JSON(), nullable=True),
    sa.Column('fixed_versions', sa.JSON(), nullable=True),
    sa.Column('vuln_index_version_id', sa.Integer(), nullable=True),
    sa.Column('detected_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['package_version_id'], ['package_version.id'], name=op.f('fk_vulnerability_package_version_id_package_version'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vuln_index_version_id'], ['vuln_index_version.id'], name=op.f('fk_vulnerability_vuln_index_version_id_vuln_index_version')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vulnerability')),
    sa.UniqueConstraint('package_version_id', 'external_id', name='uq_vulnerability_package_version_id')
    )
    op.create_index('ix_vulnerability_external_id', 'vulnerability', ['external_id'], unique=False)
    op.create_table('comment',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('request_id', sa.Integer(), nullable=False),
    sa.Column('request_item_id', sa.Integer(), nullable=True),
    sa.Column('author_id', sa.Integer(), nullable=False),
    sa.Column('author_role', sa.String(length=32), nullable=True),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('mentions', sa.JSON(), nullable=True),
    sa.Column('is_edited', sa.Boolean(), nullable=False),
    sa.Column('edited_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['author_id'], ['user.id'], name=op.f('fk_comment_author_id_user')),
    sa.ForeignKeyConstraint(['request_id'], ['moderation_request.id'], name=op.f('fk_comment_request_id_moderation_request'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['request_item_id'], ['request_item.id'], name=op.f('fk_comment_request_item_id_request_item'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_comment'))
    )
    op.create_index('ix_comment_request_id', 'comment', ['request_id'], unique=False)
    op.create_table('license_claim',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('package_version_id', sa.Integer(), nullable=False),
    sa.Column('request_item_id', sa.Integer(), nullable=True),
    sa.Column('claimed_by_id', sa.Integer(), nullable=False),
    sa.Column('url', sa.String(length=1024), nullable=False),
    sa.Column('snapshot_text', sa.Text(), nullable=True),
    sa.Column('snapshot_fetched_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('spdx_id', sa.String(length=128), nullable=True),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('decided_by_id', sa.Integer(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('decision_comment', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'approved', 'rejected')", name=op.f('ck_license_claim_claim_status')),
    sa.ForeignKeyConstraint(['claimed_by_id'], ['user.id'], name=op.f('fk_license_claim_claimed_by_id_user')),
    sa.ForeignKeyConstraint(['decided_by_id'], ['user.id'], name=op.f('fk_license_claim_decided_by_id_user')),
    sa.ForeignKeyConstraint(['package_version_id'], ['package_version.id'], name=op.f('fk_license_claim_package_version_id_package_version'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['request_item_id'], ['request_item.id'], name=op.f('fk_license_claim_request_item_id_request_item'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_license_claim'))
    )
    op.create_table('notification',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('event', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=512), nullable=False),
    sa.Column('body', sa.Text(), nullable=True),
    sa.Column('request_id', sa.Integer(), nullable=True),
    sa.Column('request_item_id', sa.Integer(), nullable=True),
    sa.Column('payload', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['request_id'], ['moderation_request.id'], name=op.f('fk_notification_request_id_moderation_request'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['request_item_id'], ['request_item.id'], name=op.f('fk_notification_request_item_id_request_item'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], name=op.f('fk_notification_user_id_user'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notification'))
    )
    op.create_index('ix_notification_user_id_read_at', 'notification', ['user_id', 'read_at'], unique=False)
    op.create_table('pipeline_step',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('request_item_id', sa.Integer(), nullable=False),
    sa.Column('step_code', sa.String(length=32), nullable=False),
    sa.Column('step_order', sa.Integer(), nullable=False),
    sa.Column('result', sa.String(length=16), nullable=False),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('details', sa.JSON(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("result IN ('pending', 'pass', 'warn', 'fail', 'skipped')", name=op.f('ck_pipeline_step_step_result')),
    sa.CheckConstraint("step_code IN ('db_check', 'blacklist', 'quarantine', 'license', 'download', 'vuln_scan', 'publish')", name=op.f('ck_pipeline_step_step_code')),
    sa.ForeignKeyConstraint(['request_item_id'], ['request_item.id'], name=op.f('fk_pipeline_step_request_item_id_request_item'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_pipeline_step')),
    sa.UniqueConstraint('request_item_id', 'step_code', name='uq_pipeline_step_request_item_id')
    )


def downgrade() -> None:
    op.drop_table('pipeline_step')
    op.drop_index('ix_notification_user_id_read_at', table_name='notification')
    op.drop_table('notification')
    op.drop_table('license_claim')
    op.drop_index('ix_comment_request_id', table_name='comment')
    op.drop_table('comment')
    op.drop_index('ix_vulnerability_external_id', table_name='vulnerability')
    op.drop_table('vulnerability')
    op.drop_index('ix_request_item_status', table_name='request_item')
    op.drop_index('ix_request_item_request_id', table_name='request_item')
    op.drop_table('request_item')
    op.drop_index('ix_artifact_package_version_id', table_name='artifact')
    op.drop_table('artifact')
    op.drop_index('ix_package_version_status', table_name='package_version')
    op.drop_index('ix_package_version_quarantine_until', table_name='package_version')
    op.drop_table('package_version')
    op.drop_index('ix_moderation_request_status', table_name='moderation_request')
    op.drop_table('moderation_request')
    op.drop_index('ix_audit_log_entity', table_name='audit_log')
    op.drop_index('ix_audit_log_created_at', table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_table('vuln_index_version')
    op.drop_table('user')
    op.drop_table('package_manager')
    op.drop_index('ix_package_name', table_name='package')
    op.drop_table('package')
    op.drop_table('license')
