-- Откат: убрать sandbox_scan из допустимых кодов шага.
--
-- Строки sandbox_scan при этом удаляются, а не остаются нарушать ограничение:
-- откат миграции, добавившей значение, обязан оставить базу в состоянии, куда
-- это значение не пролезает, иначе следующая вставка падает на ограничении,
-- которого в коде уже нет.
--
-- Что откат НЕ делает: не возвращает результат warn строкам banner_scan и не
-- возвращает пакеты в awaiting_security. Восстановить, какие именно строки
-- были warn до миграции, нечем — прежнее значение нигде не сохранено, а
-- угадывать по «info у banner_scan» нельзя: info там мог стоять и до неё.
DELETE FROM scan_report WHERE step_code = 'sandbox_scan';
DELETE FROM pipeline_step WHERE step_code = 'sandbox_scan';

ALTER TABLE scan_report DROP CONSTRAINT IF EXISTS scan_report_step_code_check;
ALTER TABLE scan_report DROP CONSTRAINT IF EXISTS ck_scan_report_step_code;
ALTER TABLE scan_report ADD CONSTRAINT scan_report_step_code_check CHECK (step_code IN (
    'banner_scan', 'sast_scan'
));

ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_step_code_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_code;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_step_code_check CHECK (step_code IN (
    'db_check', 'blacklist', 'quarantine', 'license', 'download',
    'vuln_scan', 'banner_scan', 'sast_scan', 'publish'
));
