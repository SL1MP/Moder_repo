DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM package_version
        WHERE length(version) > 128 OR length(raw_version) > 128
    ) OR EXISTS (
        SELECT 1 FROM request_item WHERE length(requested_version) > 128
    ) THEN
        RAISE EXCEPTION '0033 нельзя откатить: в базе есть версии длиннее 128 символов';
    END IF;
END $$;

ALTER TABLE request_item
    ALTER COLUMN requested_version TYPE VARCHAR(128);

ALTER TABLE package_version
    ALTER COLUMN version TYPE VARCHAR(128),
    ALTER COLUMN raw_version TYPE VARCHAR(128);
