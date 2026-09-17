-- Откат: заявки в статусе dry_run переводятся в pending, иначе ограничение
-- не встанет на существующих строках.
UPDATE moderation_request SET status = 'pending' WHERE status = 'dry_run';
ALTER TABLE moderation_request DROP CONSTRAINT moderation_request_status_check;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_status_check CHECK (status IN (
    'pending', 'awaiting_security', 'awaiting_legal', 'quarantined',
    'approved', 'partially_approved', 'rejected', 'failed'
));
