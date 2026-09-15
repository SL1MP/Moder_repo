UPDATE request_item SET status = 'queued' WHERE status = 'dry_run';
ALTER TABLE request_item DROP CONSTRAINT request_item_status_check;
ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
    'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
    'awaiting_security', 'approved', 'rejected', 'revoked', 'blacklisted', 'failed'
));
