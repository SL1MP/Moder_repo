-- Внешние проверки (прежде всего sandbox) могут занимать минуты. Раньше строка
-- pipeline_step появлялась только ПОСЛЕ завершения вызова, поэтому всё это
-- время интерфейс показывал «не начат» и создавал впечатление зависания.
-- running — фактическое состояние начатого, но ещё не завершённого шага.
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_result_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_result;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_result_check CHECK (result IN (
    'pending', 'running', 'pass', 'info', 'warn', 'fail', 'skipped'
));
