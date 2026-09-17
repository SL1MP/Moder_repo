-- Статус dry_run для заявки целиком.
--
-- Миграция 0008 (и 0005 python-версии) завела dry_run для пакета заявки, но
-- не для самой заявки. Свёртка статусов не знала про него и роняла такую
-- заявку в последнюю ветку — `rejected`. Снаружи это выглядело так: все девять
-- шагов пройдены, пакет в dry_run, а заявка «отклонена».
--
-- То же расхождение есть и в python-версии (recompute_request_status): там
-- dry_run тоже проваливается в else. Здесь оно исправлено, потому что
-- заявка в статусе «отклонена» — это не косметика: по ней разработчик делает
-- вывод, что пакет запрещён, хотя проверка прошла полностью.
--
-- Список записан литералом намеренно — см. комментарий в 0004.
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS moderation_request_status_check;
ALTER TABLE moderation_request DROP CONSTRAINT IF EXISTS ck_moderation_request_request_status;
ALTER TABLE moderation_request ADD CONSTRAINT moderation_request_status_check CHECK (status IN (
    'pending', 'awaiting_security', 'awaiting_legal', 'quarantined',
    'approved', 'partially_approved', 'dry_run', 'rejected', 'failed'
));
