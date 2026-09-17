-- Возврат схемы без отмены.
--
-- Отменённые пакеты и заявки переводятся в `rejected`: другого «дальше не
-- поедет» в прежней схеме нет. Отличить их потом можно только по аудиту
-- (действие `request_cancelled`) — это цена откату, и она невозвратная.
UPDATE request_item SET status = 'rejected' WHERE status = 'cancelled';
UPDATE moderation_request SET status = 'rejected' WHERE status = 'cancelled';

ALTER TABLE request_item DROP CONSTRAINT IF EXISTS request_item_status_check;
ALTER TABLE request_item DROP CONSTRAINT IF EXISTS ck_request_item_item_status;
ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
    'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
    'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked',
    'blacklisted', 'failed'
));

ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_status_check;
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_request_status;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_status_check CHECK (status IN (
    'pending', 'awaiting_security', 'awaiting_legal', 'quarantined',
    'approved', 'partially_approved', 'dry_run', 'rejected', 'failed'
));
