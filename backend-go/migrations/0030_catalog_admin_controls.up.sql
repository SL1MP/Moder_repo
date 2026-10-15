-- Удаление опубликованной версии из web-интерфейса — отдельное действие,
-- отличное от отзыва DevSecOps. Причина хранится в status_reason, автор и
-- полный снимок изменения — в audit_log.
ALTER TABLE package_version
    DROP CONSTRAINT IF EXISTS package_version_status_check;

ALTER TABLE package_version
    ADD CONSTRAINT package_version_status_check CHECK (status IN (
        'new', 'checking', 'quarantined', 'awaiting_legal', 'license_claimed',
        'awaiting_security', 'approved', 'deleted', 'rejected', 'revoked',
        'blacklisted', 'failed'
    ));

-- Web-версия политики лицензий. Строка отсутствует, пока список ни разу не
-- сохраняли: тогда источником остаётся config/licenses.yml.
CREATE TABLE IF NOT EXISTS license_policy (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    entries JSONB NOT NULL CHECK (jsonb_typeof(entries) = 'array'),
    updated_by_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
