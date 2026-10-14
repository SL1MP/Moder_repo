-- Фоновая синхронизация доверенных moderated-репозиториев с web-каталогом.
-- Строка описывает запуск, а не состояние пакета: служебные результаты
-- сверки не должны попадать в package_version.status.
ALTER TABLE artifact ALTER COLUMN size_bytes TYPE BIGINT;

CREATE TABLE IF NOT EXISTS artifact_catalog_sync_run (
    id BIGSERIAL PRIMARY KEY,
    status VARCHAR(16) NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    run_trigger VARCHAR(16) NOT NULL CHECK (run_trigger IN ('startup', 'schedule', 'manual', 'cli')),
    managers JSONB NOT NULL DEFAULT '[]'::jsonb,
    requested_by_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
    discovered INTEGER NOT NULL DEFAULT 0,
    imported INTEGER NOT NULL DEFAULT 0,
    updated INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_artifact_catalog_sync_run_created_at
    ON artifact_catalog_sync_run (created_at DESC);

-- Одновременно выполняется не больше одного обхода: при нескольких worker
-- один заберёт запуск, остальные продолжат обрабатывать обычную очередь.
CREATE UNIQUE INDEX IF NOT EXISTS uq_artifact_catalog_sync_one_running
    ON artifact_catalog_sync_run ((status)) WHERE status = 'running';

CREATE UNIQUE INDEX IF NOT EXISTS uq_artifact_catalog_sync_one_queued
    ON artifact_catalog_sync_run ((status)) WHERE status = 'queued';
