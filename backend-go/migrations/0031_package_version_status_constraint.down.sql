UPDATE package_version
SET status = 'revoked',
    status_reason = COALESCE(status_reason, 'Удалено администратором')
WHERE status = 'deleted';

ALTER TABLE package_version
    DROP CONSTRAINT IF EXISTS ck_package_version_version_status;

ALTER TABLE package_version
    DROP CONSTRAINT IF EXISTS package_version_status_check;

ALTER TABLE package_version
    ADD CONSTRAINT package_version_status_check CHECK (status IN (
        'new', 'checking', 'quarantined', 'awaiting_legal', 'license_claimed',
        'awaiting_security', 'approved', 'rejected', 'revoked',
        'blacklisted', 'failed'
    ));
