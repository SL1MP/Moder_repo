-- Откат: вернуть прежние имена столбцов.
--
-- Значения не восстанавливаются: какой бакет S3 стоял в staging_repo до
-- миграции, нигде не сохранено. Откат возвращает форму схемы, а не данные —
-- и умолчать об этом нельзя.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'artifact' AND column_name = 'staging_repo') THEN
        ALTER TABLE artifact RENAME COLUMN staging_repo TO s3_bucket;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'artifact' AND column_name = 'staging_path') THEN
        ALTER TABLE artifact RENAME COLUMN staging_path TO s3_key;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'artifact' AND column_name = 'staged_at') THEN
        ALTER TABLE artifact RENAME COLUMN staged_at TO s3_uploaded_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'artifact' AND column_name = 'staging_cleared_at') THEN
        ALTER TABLE artifact RENAME COLUMN staging_cleared_at TO s3_deleted_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'scan_report' AND column_name = 'repo') THEN
        ALTER TABLE scan_report RENAME COLUMN repo TO bucket;
    END IF;
END $$;
