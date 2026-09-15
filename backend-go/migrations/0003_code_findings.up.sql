-- Находки сканеров содержимого: политические баннеры и SAST — см.
-- backend/alembic/versions/0003_code_findings.py.
CREATE TABLE code_finding (
    id SERIAL PRIMARY KEY,
    package_version_id INTEGER NOT NULL REFERENCES package_version (id) ON DELETE CASCADE,
    scanner VARCHAR(32) NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    message TEXT,
    file_path VARCHAR(1024),
    line INTEGER,
    matched TEXT,
    detected_at TIMESTAMPTZ
);
CREATE INDEX ix_code_finding_package_version_id ON code_finding (package_version_id);
CREATE INDEX ix_code_finding_scanner ON code_finding (scanner);
