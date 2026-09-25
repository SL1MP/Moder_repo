UPDATE pipeline_step
SET result = 'pending', finished_at = NULL
WHERE result = 'running';

ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_result_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_result;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_result_check CHECK (result IN (
    'pending', 'pass', 'info', 'warn', 'fail', 'skipped'
));
