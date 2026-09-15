DELETE FROM pipeline_step WHERE step_code IN ('banner_scan', 'sast_scan');
ALTER TABLE pipeline_step DROP CONSTRAINT pipeline_step_step_code_check;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_step_code_check CHECK (step_code IN (
    'db_check', 'blacklist', 'quarantine', 'license', 'download', 'vuln_scan', 'publish'
));
