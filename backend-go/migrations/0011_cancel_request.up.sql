-- Отмена заявки автором: статус `cancelled` для пакета и для заявки.
--
-- Зачем: пакеты перестали быть нужны (взяли другую библиотеку, переписали
-- код, ошиблись версией), а заявка висит в очереди роли и выглядит как работа,
-- которую кто-то должен сделать. Своего статуса для этого не было, и закрыть
-- заявку было нечем: `rejected` — это решение роли («нельзя»), а не отказ
-- автора («уже не нужно»), и путать их в отчётности нельзя.
--
-- Отмена — не удаление: строки остаются, аудит и обсуждение сохраняются.
--
-- Имена ограничений сняты по обоим соглашениям — см. комментарий в 0010.
ALTER TABLE request_item DROP CONSTRAINT IF EXISTS request_item_status_check;
ALTER TABLE request_item DROP CONSTRAINT IF EXISTS ck_request_item_item_status;
ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
    'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
    'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked',
    'blacklisted', 'cancelled', 'failed'
));

ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_status_check;
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_request_status;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_status_check CHECK (status IN (
    'pending', 'awaiting_security', 'awaiting_legal', 'quarantined',
    'approved', 'partially_approved', 'dry_run', 'rejected', 'cancelled', 'failed'
));
