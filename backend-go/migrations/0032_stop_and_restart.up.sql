-- Остановка отдельного пакета без закрытия всей заявки.
--
-- stopped отличается от cancelled: cancelled означает, что автор закрыл
-- заявку целиком, stopped — что конкретный прогон намеренно прервали и его
-- можно продолжить в той же заявке. Поздняя успешная публикация той же версии
-- в другой заявке синхронизирует stopped-пакет до approved.
ALTER TABLE request_item DROP CONSTRAINT IF EXISTS request_item_status_check;
ALTER TABLE request_item DROP CONSTRAINT IF EXISTS ck_request_item_item_status;
ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
    'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
    'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked',
    'blacklisted', 'stopped', 'cancelled', 'failed'
));

ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_status_check;
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_request_status;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_status_check CHECK (status IN (
    'pending', 'awaiting_security', 'awaiting_legal', 'quarantined',
    'approved', 'partially_approved', 'dry_run', 'rejected', 'stopped',
    'cancelled', 'failed'
));
