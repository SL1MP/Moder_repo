-- Статус dry_run для request_item.
--
-- Шаг публикации в режиме ARTIFACT_DRY_RUN завершает обработку успешно
-- (terminal), но публикации не было: реального артефакта по команде установки
-- ещё нет, и помечать пакет approved нельзя. В Python-версии это лечилось
-- отдельным статусом (её миграция 0005); при переносе на Go статус в коде
-- появился, а в CHECK-ограничении — нет, и прогон падал на
-- CheckViolation request_item_status_check.
--
-- Ровно эта мина уже стоила бою одного падения (см. handoff, п. 8.2):
-- расхождение между константой в коде и CHECK'ом в миграции. Здесь его поймал
-- интеграционный тест на живой базе — тесты, поднимающие схему из моделей, его
-- бы не увидели.
--
-- Список записан литералом намеренно — см. комментарий в 0004.
ALTER TABLE request_item DROP CONSTRAINT request_item_status_check;
ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
    'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
    'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked', 'blacklisted', 'failed'
));
