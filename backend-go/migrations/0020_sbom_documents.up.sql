-- CycloneDX SBOM для проверенного артефакта. Для Docker строк несколько — по
-- одной на платформу; для остальных поддерживаемых менеджеров одна.
CREATE TABLE sbom_document (
    id                 BIGSERIAL PRIMARY KEY,
    request_item_id    BIGINT NOT NULL REFERENCES request_item(id) ON DELETE CASCADE,
    package_version_id BIGINT NOT NULL REFERENCES package_version(id) ON DELETE CASCADE,
    manager            TEXT NOT NULL,
    platform           TEXT NOT NULL DEFAULT '',
    filename           TEXT NOT NULL,
    format             TEXT NOT NULL DEFAULT 'cyclonedx-json',
    spec_version       TEXT NOT NULL DEFAULT '1.4',
    storage_key        TEXT NOT NULL,
    size_bytes         BIGINT NOT NULL,
    sha256             TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_sbom_document_item_platform UNIQUE (request_item_id, platform),
    CONSTRAINT uq_sbom_document_storage_key UNIQUE (storage_key),
    CONSTRAINT sbom_document_manager_check CHECK (manager IN (
        'npm', 'nuget', 'pypi', 'maven', 'go', 'conan', 'docker'
    )),
    CONSTRAINT sbom_document_format_check CHECK (format = 'cyclonedx-json')
);

CREATE INDEX ix_sbom_document_package_version ON sbom_document(package_version_id);

ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS pipeline_step_step_code_check;
ALTER TABLE pipeline_step DROP CONSTRAINT IF EXISTS ck_pipeline_step_step_code;
ALTER TABLE pipeline_step ADD CONSTRAINT pipeline_step_step_code_check CHECK (step_code IN (
    'db_check', 'blacklist', 'quarantine', 'license', 'download',
    'vuln_scan', 'sandbox_scan', 'sbom', 'publish',
    'banner_scan', 'sast_scan'
));
