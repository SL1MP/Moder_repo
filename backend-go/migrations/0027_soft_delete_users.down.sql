DROP INDEX IF EXISTS ix_user_deleted_at;
ALTER TABLE "user" DROP COLUMN IF EXISTS deleted_at;
