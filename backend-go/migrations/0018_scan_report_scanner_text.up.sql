-- SANDBOX_URL входит в отображаемое имя сканера: sandbox (https://...).
-- Ограничение VARCHAR(32), оставшееся от коротких имён yara/semgrep,
-- отклоняло корректный отчёт песочницы ещё после успешного вердикта.
ALTER TABLE scan_report
    ALTER COLUMN scanner TYPE TEXT;
