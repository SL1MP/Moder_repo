ALTER TABLE "user"
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_user_deleted_at ON "user" (deleted_at);
