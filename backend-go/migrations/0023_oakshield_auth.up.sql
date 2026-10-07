-- Oakshield-compatible authentication and user lifecycle.

ALTER TABLE "user"
    ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'local'
        CHECK (source IN ('local', 'oidc')),
    ADD COLUMN is_superuser BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN description TEXT NOT NULL DEFAULT '';

UPDATE "user"
SET source = CASE
        WHEN subject IS NOT NULL AND subject <> '' AND subject NOT LIKE 'local:%' THEN 'oidc'
        ELSE 'local'
    END,
    is_superuser = roles ? 'admin';

CREATE UNIQUE INDEX user_oidc_subject_idx
    ON "user" (source, subject)
    WHERE subject IS NOT NULL;

CREATE TABLE refresh_token (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX refresh_token_user_idx ON refresh_token (user_id);

CREATE TABLE api_token (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX api_token_user_idx ON api_token (user_id);

CREATE TABLE oidc_integration (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    issuer TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    client_secret TEXT NOT NULL DEFAULT '',
    public_base_url TEXT NOT NULL DEFAULT '',
    button_label TEXT NOT NULL DEFAULT 'Keycloak (SSO)',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO oidc_integration (id) VALUES (TRUE);

CREATE TABLE login_throttle (
    scope VARCHAR(8) NOT NULL CHECK (scope IN ('user', 'ip')),
    key TEXT NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    first_failure_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (scope, key)
);
CREATE INDEX login_throttle_updated_idx ON login_throttle (updated_at);
