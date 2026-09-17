-- Возврат к блокирующему SAST.
--
-- Строки info переводим назад в warn: другого значения для «шаг не пройден» в
-- прежней схеме нет. Пакеты, которые up-миграция вернула в очередь, обратно не
-- отправляются — они к этому моменту уже обработаны, и отменить это нельзя.
UPDATE pipeline_step SET result = 'warn' WHERE result = 'info';

ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_result_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_result;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_result_check CHECK (result IN (
    'pending', 'pass', 'warn', 'fail', 'skipped'
));
