-- Начальная схема сервиса модерации пакетов.
-- Порт Alembic-миграции backend/alembic/versions/0001_initial_schema.py — см.
-- docs/migration-to-go.md. Отличие от Python-схемы: JSON -> JSONB (там JSON был
-- уступкой ради переносимости на SQLite в юнит-тестах, см. docs/testing.md; pgx
-- работает только с Postgres, уступка не нужна).

CREATE TABLE IF NOT EXISTS license (
    id SERIAL PRIMARY KEY,
    spdx_id VARCHAR(128) NOT NULL UNIQUE,
    name VARCHAR(255),
    allowed BOOLEAN NOT NULL,
    url VARCHAR(1024),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS package (
    id SERIAL PRIMARY KEY,
    manager VARCHAR(16) NOT NULL CHECK (manager IN ('pypi', 'npm', 'go', 'nuget')),
    name VARCHAR(512) NOT NULL,
    display_name VARCHAR(512) NOT NULL,
    confirmed_license_spdx VARCHAR(128),
    confirmed_license_version VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_package_manager_name UNIQUE (manager, name)
);
CREATE INDEX IF NOT EXISTS ix_package_name ON package (name);

CREATE TABLE IF NOT EXISTS package_manager (
    id SERIAL PRIMARY KEY,
    code VARCHAR(16) NOT NULL UNIQUE CHECK (code IN ('pypi', 'npm', 'go', 'nuget')),
    title VARCHAR(64) NOT NULL,
    entry_format VARCHAR(64) NOT NULL,
    enabled BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS "user" (
    id SERIAL PRIMARY KEY,
    subject VARCHAR(255) UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255),
    full_name VARCHAR(255),
    roles JSONB NOT NULL,
    is_service BOOLEAN NOT NULL,
    is_active BOOLEAN NOT NULL,
    password_hash VARCHAR(255),
    last_login_at TIMESTAMPTZ,
    gitlab_username VARCHAR(255),
    gitlab_access_token_enc TEXT,
    gitlab_refresh_token_enc TEXT,
    gitlab_token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vuln_index_version (
    id SERIAL PRIMARY KEY,
    version VARCHAR(128) NOT NULL UNIQUE,
    source VARCHAR(32) NOT NULL,
    checksum VARCHAR(128),
    remote_path VARCHAR(512),
    local_path VARCHAR(512),
    published_at TIMESTAMPTZ,
    downloaded_at TIMESTAMPTZ,
    record_count INTEGER,
    is_active BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    actor_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
    actor_name VARCHAR(255) NOT NULL,
    actor_role VARCHAR(32),
    action VARCHAR(64) NOT NULL,
    entity_type VARCHAR(64) NOT NULL,
    entity_id VARCHAR(64),
    old_value JSONB,
    new_value JSONB,
    source VARCHAR(16) NOT NULL,
    request_id VARCHAR(64),
    ip VARCHAR(64),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_log_created_at ON audit_log (created_at);
CREATE INDEX IF NOT EXISTS ix_audit_log_entity ON audit_log (entity_type, entity_id);

CREATE TABLE IF NOT EXISTS moderation_request (
    id SERIAL PRIMARY KEY,
    author_id INTEGER NOT NULL REFERENCES "user" (id),
    author_role VARCHAR(32),
    manager VARCHAR(16) NOT NULL CHECK (manager IN ('pypi', 'npm', 'go', 'nuget')),
    reason TEXT,
    status VARCHAR(32) NOT NULL CHECK (status IN (
        'pending', 'awaiting_security', 'awaiting_legal', 'quarantined',
        'approved', 'partially_approved', 'rejected', 'failed'
    )),
    source VARCHAR(16) NOT NULL CHECK (source IN ('api', 'ui', 'cli', 'gitlab')),
    idempotency_key VARCHAR(255) UNIQUE,
    origin_file VARCHAR(512),
    include_transitive BOOLEAN NOT NULL,
    warnings JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_moderation_request_status ON moderation_request (status);

CREATE TABLE IF NOT EXISTS package_version (
    id SERIAL PRIMARY KEY,
    package_id INTEGER NOT NULL REFERENCES package (id) ON DELETE CASCADE,
    version VARCHAR(128) NOT NULL,
    raw_version VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN (
        'new', 'checking', 'quarantined', 'awaiting_legal', 'license_claimed',
        'awaiting_security', 'approved', 'rejected', 'revoked', 'blacklisted', 'failed'
    )),
    published_at TIMESTAMPTZ,
    quarantine_until TIMESTAMPTZ,
    license_spdx VARCHAR(128),
    license_source VARCHAR(32),
    license_raw TEXT,
    registry_metadata JSONB,
    vuln_index_version_id INTEGER REFERENCES vuln_index_version (id),
    max_vuln_score DOUBLE PRECISION,
    approved_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    status_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_package_version_package_id UNIQUE (package_id, version)
);
CREATE INDEX IF NOT EXISTS ix_package_version_quarantine_until ON package_version (quarantine_until);
CREATE INDEX IF NOT EXISTS ix_package_version_status ON package_version (status);

CREATE TABLE IF NOT EXISTS artifact (
    id SERIAL PRIMARY KEY,
    package_version_id INTEGER NOT NULL REFERENCES package_version (id) ON DELETE CASCADE,
    filename VARCHAR(512) NOT NULL,
    source_url VARCHAR(2048),
    size_bytes INTEGER,
    sha256 VARCHAR(128),
    declared_checksum VARCHAR(160),
    checksum_algo VARCHAR(16),
    s3_bucket VARCHAR(128),
    s3_key VARCHAR(1024),
    s3_uploaded_at TIMESTAMPTZ,
    s3_deleted_at TIMESTAMPTZ,
    nexus_url VARCHAR(2048),
    published_at TIMESTAMPTZ,
    status VARCHAR(24) NOT NULL CHECK (status IN ('downloaded', 'scanned', 'published', 'purged', 'failed'))
);
CREATE INDEX IF NOT EXISTS ix_artifact_package_version_id ON artifact (package_version_id);

CREATE TABLE IF NOT EXISTS request_item (
    id SERIAL PRIMARY KEY,
    request_id INTEGER NOT NULL REFERENCES moderation_request (id) ON DELETE CASCADE,
    package_version_id INTEGER NOT NULL REFERENCES package_version (id) ON DELETE CASCADE,
    requested_name VARCHAR(512) NOT NULL,
    requested_version VARCHAR(128) NOT NULL,
    dependency_kind VARCHAR(16) NOT NULL CHECK (dependency_kind IN ('direct', 'transitive')),
    status VARCHAR(32) NOT NULL CHECK (status IN (
        'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
        'awaiting_security', 'approved', 'rejected', 'revoked', 'blacklisted', 'failed'
    )),
    current_step VARCHAR(32),
    next_action TEXT,
    blocked_reason TEXT,
    waiting_since TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_request_item_request_id ON request_item (request_id);
CREATE INDEX IF NOT EXISTS ix_request_item_status ON request_item (status);

CREATE TABLE IF NOT EXISTS vulnerability (
    id SERIAL PRIMARY KEY,
    package_version_id INTEGER NOT NULL REFERENCES package_version (id) ON DELETE CASCADE,
    external_id VARCHAR(64) NOT NULL,
    aliases JSONB,
    summary TEXT,
    cvss_vector VARCHAR(256),
    cvss_score DOUBLE PRECISION,
    score DOUBLE PRECISION NOT NULL,
    severity VARCHAR(16),
    url VARCHAR(1024),
    affected_ranges JSONB,
    fixed_versions JSONB,
    vuln_index_version_id INTEGER REFERENCES vuln_index_version (id),
    detected_at TIMESTAMPTZ,
    CONSTRAINT uq_vulnerability_package_version_id UNIQUE (package_version_id, external_id)
);
CREATE INDEX IF NOT EXISTS ix_vulnerability_external_id ON vulnerability (external_id);

CREATE TABLE IF NOT EXISTS comment (
    id SERIAL PRIMARY KEY,
    request_id INTEGER NOT NULL REFERENCES moderation_request (id) ON DELETE CASCADE,
    request_item_id INTEGER REFERENCES request_item (id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES "user" (id),
    author_role VARCHAR(32),
    body TEXT NOT NULL,
    mentions JSONB,
    is_edited BOOLEAN NOT NULL,
    edited_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_comment_request_id ON comment (request_id);

CREATE TABLE IF NOT EXISTS license_claim (
    id SERIAL PRIMARY KEY,
    package_version_id INTEGER NOT NULL REFERENCES package_version (id) ON DELETE CASCADE,
    request_item_id INTEGER REFERENCES request_item (id) ON DELETE SET NULL,
    claimed_by_id INTEGER NOT NULL REFERENCES "user" (id),
    url VARCHAR(1024) NOT NULL,
    snapshot_text TEXT,
    snapshot_fetched_at TIMESTAMPTZ,
    spdx_id VARCHAR(128),
    comment TEXT,
    status VARCHAR(16) NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    decided_by_id INTEGER REFERENCES "user" (id),
    decided_at TIMESTAMPTZ,
    decision_comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notification (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
    event VARCHAR(64) NOT NULL,
    title VARCHAR(512) NOT NULL,
    body TEXT,
    request_id INTEGER REFERENCES moderation_request (id) ON DELETE CASCADE,
    request_item_id INTEGER REFERENCES request_item (id) ON DELETE CASCADE,
    payload JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    read_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_notification_user_id_read_at ON notification (user_id, read_at);

CREATE TABLE IF NOT EXISTS pipeline_step (
    id SERIAL PRIMARY KEY,
    request_item_id INTEGER NOT NULL REFERENCES request_item (id) ON DELETE CASCADE,
    step_code VARCHAR(32) NOT NULL CHECK (step_code IN (
        'db_check', 'blacklist', 'quarantine', 'license', 'download', 'vuln_scan', 'publish'
    )),
    step_order INTEGER NOT NULL,
    result VARCHAR(16) NOT NULL CHECK (result IN ('pending', 'pass', 'warn', 'fail', 'skipped')),
    message TEXT,
    details JSONB,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CONSTRAINT uq_pipeline_step_request_item_id UNIQUE (request_item_id, step_code)
);
