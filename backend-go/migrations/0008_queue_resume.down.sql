DROP INDEX IF EXISTS ix_request_item_queue;
ALTER TABLE request_item DROP COLUMN IF EXISTS attempts;
ALTER TABLE request_item DROP COLUMN IF EXISTS resume_from_step;
