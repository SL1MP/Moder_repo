-- Коды шагов banner_scan и sast_scan в CHECK-ограничении — см.
-- backend/alembic/versions/0004_step_codes_content_scans.py.
--
-- Список кодов шагов записан литералом намеренно: миграция — снимок состояния
-- на своей ревизии. В Python-версии расхождение между константой STEP_CODES и
-- этим CHECK'ом уже приводило к CheckViolation в бою (тесты не ловили, потому
-- что схема в тестах поднималась из моделей, а не из миграций) — при переносе
-- на Go источник истины для допустимых step_code при вставке строки —
-- ИМЕННО эта миграция, а не Go-константа; при добавлении нового шага
-- обязательна новая миграция, обновляющая это ограничение, никогда — правка
-- этого файла задним числом.
ALTER TABLE pipeline_step DROP CONSTRAINT pipeline_step_step_code_check;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_step_code_check CHECK (step_code IN (
    'db_check', 'blacklist', 'quarantine', 'license', 'download',
    'vuln_scan', 'banner_scan', 'sast_scan', 'publish'
));
