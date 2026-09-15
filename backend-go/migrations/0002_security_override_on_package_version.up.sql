-- Решение DevSecOps «публиковать несмотря на уязвимости» — см.
-- backend/alembic/versions/0002_security_override_on_package_version.py.
ALTER TABLE package_version ADD COLUMN security_override_at TIMESTAMPTZ;
ALTER TABLE package_version ADD COLUMN security_override_by_id INTEGER REFERENCES "user" (id);
ALTER TABLE package_version ADD COLUMN security_override_comment TEXT;
