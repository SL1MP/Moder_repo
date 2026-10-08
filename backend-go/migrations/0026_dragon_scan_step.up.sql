ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_step_code_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_code;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_step_code_check CHECK (step_code IN (
    'db_check', 'blacklist', 'quarantine', 'license', 'download',
    'dragon_scan', 'vuln_scan', 'sandbox_scan', 'sbom', 'publish',
    'banner_scan', 'sast_scan'
));

