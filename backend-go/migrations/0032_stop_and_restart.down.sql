UPDATE request_item
SET status = 'cancelled',
    blocked_reason = COALESCE(blocked_reason, 'Проверка была остановлена')
WHERE status = 'stopped';

UPDATE moderation_request SET status = 'cancelled' WHERE status = 'stopped';

ALTER TABLE request_item DROP CONSTRAINT IF EXISTS request_item_status_check;
ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
    'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
    'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked',
    'blacklisted', 'cancelled', 'failed'
));

ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_status_check;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_status_check CHECK (status IN (
    'pending', 'awaiting_security', 'awaiting_legal', 'quarantined',
    'approved', 'partially_approved', 'dry_run', 'rejected', 'cancelled', 'failed'
));
