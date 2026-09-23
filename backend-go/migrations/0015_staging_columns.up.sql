-- Промежуточная зона вместо S3: столбцы artifact называются по существу.
--
-- Отказ от S3 (решение пользователя) меняет не только реализацию хранилища, но
-- и смысл этих столбцов. Раньше в них лежали бакет и ключ объекта в
-- S3-совместимом хранилище; теперь — репозиторий артефактори и путь файла в
-- нём. Оставить имена s3_* значило бы завести в схеме ложь ровно того сорта,
-- который этот проект уже ловил дважды: имя, которое рассказывает про систему,
-- выведенную из эксплуатации, отправляет искать проблему не туда.
--
-- ALTER ... RENAME COLUMN не переписывает таблицу и не берёт долгой блокировки:
-- меняется только запись в каталоге. Данные переносить не нужно — значения
-- остаются на месте, меняется их трактовка вызывающим кодом.
--
-- IF EXISTS на каждом шаге: набор миграций накатывается руками, и повторный
-- прогон не должен ломаться (тот же приём, что в 0004, 0010, 0013).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'artifact' AND column_name = 's3_bucket') THEN
        ALTER TABLE artifact RENAME COLUMN s3_bucket TO staging_repo;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'artifact' AND column_name = 's3_key') THEN
        ALTER TABLE artifact RENAME COLUMN s3_key TO staging_path;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'artifact' AND column_name = 's3_uploaded_at') THEN
        ALTER TABLE artifact RENAME COLUMN s3_uploaded_at TO staged_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'artifact' AND column_name = 's3_deleted_at') THEN
        ALTER TABLE artifact RENAME COLUMN s3_deleted_at TO staging_cleared_at;
    END IF;
END $$;

-- То же у отчётов: bucket стал репозиторием артефактори.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'scan_report' AND column_name = 'bucket') THEN
        ALTER TABLE scan_report RENAME COLUMN bucket TO repo;
    END IF;
END $$;

-- Пути в промежуточной зоне остались прежними по форме
-- ({manager}/{name}/{version}/{filename}), поэтому переписывать значения не
-- надо. А вот репозиторий сменился: в столбце лежит имя бакета S3, которого
-- больше нет. Ставим NULL — «где лежал, неизвестно» честнее, чем имя
-- несуществующего бакета, и уборка по таким строкам всё равно идёт по пути, а
-- не по репозиторию.
--
-- Только для строк, которые ещё не вычищены: у вычищенных столбец уже ни на
-- что не влияет, а трогать историю незачем.
UPDATE artifact SET staging_repo = NULL
WHERE staging_cleared_at IS NULL AND staging_repo IS NOT NULL;
