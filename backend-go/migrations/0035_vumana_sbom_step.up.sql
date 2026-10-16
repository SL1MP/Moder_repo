ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_step_code_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_code;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_step_code_check CHECK (step_code IN (
    'db_check', 'blacklist', 'quarantine', 'download', 'license',
    'dragon_scan', 'vuln_scan', 'sandbox_scan', 'sbom', 'sbom_upload', 'publish',
    'banner_scan', 'sast_scan'
));

-- Download is now the common prerequisite of the parallel group. Keep the
-- history of already-created requests in the same visual order as new runs.
UPDATE pipeline_step
SET step_order = CASE step_code
    WHEN 'db_check' THEN 0
    WHEN 'blacklist' THEN 1
    WHEN 'quarantine' THEN 2
    WHEN 'download' THEN 3
    WHEN 'license' THEN 4
    WHEN 'dragon_scan' THEN 5
    WHEN 'vuln_scan' THEN 6
    WHEN 'sandbox_scan' THEN 7
    WHEN 'sbom' THEN 8
    WHEN 'sbom_upload' THEN 9
    WHEN 'publish' THEN 10
    ELSE step_order
END;
