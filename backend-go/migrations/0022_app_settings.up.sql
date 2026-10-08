-- Настройки, которые администратор меняет из web-интерфейса.
--
-- .env остаётся источником начальных значений и секретов. Значения из этой
-- таблицы имеют приоритет над .env. После сохранения приложение отправляет
-- PostgreSQL NOTIFY, а api-go/worker-go автоматически корректно
-- перезапускаются и загружают новые значения.
CREATE TABLE IF NOT EXISTS app_setting (
    key VARCHAR(128) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_by_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_app_setting_updated_at ON app_setting (updated_at);
