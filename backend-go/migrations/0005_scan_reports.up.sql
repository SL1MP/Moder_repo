-- Отчёты о прогонах сканеров содержимого.
--
-- Зачем отдельная таблица, если находки уже лежат в code_finding: code_finding
-- отвечает на вопрос «что показать в карточке заявки сейчас» и перезаписывается
-- на каждом прогоне; scan_report — снимок прогона, по которому DevSecOps
-- объясняет решение, а разработчик понимает, что чинить. Снимок обязан
-- пережить и повторный прогон, и удаление артефакта из карантинной зоны.
--
-- Сами файлы (JSON и HTML) лежат в объектном хранилище под префиксом reports/;
-- здесь — ключи и сводка, чтобы список отчётов строился без похода в хранилище.
--
-- Список допустимых значений записан литералом намеренно: миграция — снимок
-- состояния на своей ревизии, и сторожевой тест сверяет литералы с константами
-- в коде. Не собирать в цикле — см. комментарий в 0004.
CREATE TABLE IF NOT EXISTS scan_report (
    id SERIAL PRIMARY KEY,
    request_item_id INTEGER NOT NULL REFERENCES request_item (id) ON DELETE CASCADE,
    package_version_id INTEGER NOT NULL REFERENCES package_version (id) ON DELETE CASCADE,

    -- Код шага, породившего отчёт: banner_scan или sast_scan.
    step_code VARCHAR(32) NOT NULL CHECK (step_code IN ('banner_scan', 'sast_scan')),
    scanner VARCHAR(32) NOT NULL,
    rules VARCHAR(512),

    -- Состояние прогона. unavailable — проверка НЕ состоялась; это не «чисто»,
    -- и отличать его от clean обязательно.
    state VARCHAR(16) NOT NULL CHECK (state IN ('clean', 'findings', 'unavailable')),
    threshold VARCHAR(16) NOT NULL,
    findings_total INTEGER NOT NULL DEFAULT 0,
    findings_blocking INTEGER NOT NULL DEFAULT 0,
    worst_severity VARCHAR(16),
    detail TEXT,

    -- Ключи файлов в объектном хранилище.
    json_key VARCHAR(1024) NOT NULL,
    html_key VARCHAR(1024) NOT NULL,
    bucket VARCHAR(128),

    duration_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Один актуальный отчёт на пару (пакет заявки, шаг): повторный прогон
    -- обновляет его, а не плодит строки. История прогонов живёт в audit_log,
    -- дублировать её здесь незачем.
    CONSTRAINT uq_scan_report_item_step UNIQUE (request_item_id, step_code)
);
CREATE INDEX IF NOT EXISTS ix_scan_report_package_version_id ON scan_report (package_version_id);
CREATE INDEX IF NOT EXISTS ix_scan_report_request_item_id ON scan_report (request_item_id);
