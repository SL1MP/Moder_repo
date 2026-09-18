DROP INDEX IF EXISTS ix_request_item_parent_item_id;
ALTER TABLE request_item DROP COLUMN IF EXISTS required_range;
ALTER TABLE request_item DROP COLUMN IF EXISTS depth;
ALTER TABLE request_item DROP COLUMN IF EXISTS parent_item_id;
ALTER TABLE moderation_request DROP COLUMN IF EXISTS resolve_summary;
ALTER TABLE moderation_request DROP COLUMN IF EXISTS resolve_depth;
