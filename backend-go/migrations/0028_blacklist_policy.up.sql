-- Web-версия blacklist. Строка отсутствует, пока администратор ни разу не
-- сохранял редактор: в этом случае сервис продолжает читать blacklist.yml.
-- JSONB хранит весь список одним документом, чтобы новая политика применялась
-- атомарно и ни один worker не увидел половину старых и половину новых правил.
CREATE TABLE IF NOT EXISTS blacklist_policy (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    rules JSONB NOT NULL CHECK (jsonb_typeof(rules) = 'array'),
    updated_by_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
