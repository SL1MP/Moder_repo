DELETE FROM pipeline_step WHERE step_code = 'sbom_upload';
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_step_code_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_code;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_step_code_check CHECK (step_code IN (
    'db_check', 'blacklist', 'quarantine', 'license', 'download',
    'dragon_scan', 'vuln_scan', 'sandbox_scan', 'sbom', 'publish',
    'banner_scan', 'sast_scan'
));

UPDATE pipeline_step
SET step_order = CASE step_code
    WHEN 'db_check' THEN 0
    WHEN 'blacklist' THEN 1
    WHEN 'quarantine' THEN 2
    WHEN 'license' THEN 3
    WHEN 'download' THEN 4
    WHEN 'dragon_scan' THEN 5
    WHEN 'vuln_scan' THEN 6
    WHEN 'sandbox_scan' THEN 7
    WHEN 'sbom' THEN 8
    WHEN 'publish' THEN 9
    ELSE step_order
END;
