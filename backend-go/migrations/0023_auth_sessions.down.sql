DROP TABLE IF EXISTS login_throttle;
DROP TABLE IF EXISTS oidc_integration;
DROP TABLE IF EXISTS api_token;
DROP TABLE IF EXISTS refresh_token;
DROP INDEX IF EXISTS user_oidc_subject_idx;
ALTER TABLE "user"
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS must_change_password,
    DROP COLUMN IF EXISTS is_superuser,
    DROP COLUMN IF EXISTS source;
