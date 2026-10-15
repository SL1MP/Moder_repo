-- Схемы, изначально созданные Alembic, используют имя ограничения из его
-- naming convention. Миграция 0030 обновляла только имя Go-схемы, поэтому
-- старое ограничение продолжало запрещать статус deleted.
--
-- Это отдельная миграция намеренно: на стендах, где 0030 уже отмечена как
-- применённая, изменение её файла больше никогда не выполнится.
ALTER TABLE package_version
    DROP CONSTRAINT IF EXISTS ck_package_version_version_status;

ALTER TABLE package_version
    DROP CONSTRAINT IF EXISTS package_version_status_check;

ALTER TABLE package_version
    ADD CONSTRAINT package_version_status_check CHECK (status IN (
        'new', 'checking', 'quarantined', 'awaiting_legal', 'license_claimed',
        'awaiting_security', 'approved', 'deleted', 'rejected', 'revoked',
        'blacklisted', 'failed'
    ));
