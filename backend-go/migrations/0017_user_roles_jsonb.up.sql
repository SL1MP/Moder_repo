-- В старой Python-схеме user.roles создавалась как json, а Go-запрос поиска
-- получателей использует оператор jsonb ?|. На обновлённой базе это приводило
-- к `operator does not exist: json ?| unknown` и уведомления не создавались.
-- Новые установки уже получают JSONB из 0001; условие делает миграцию
-- безопасной и для них, и для стендов, исправленных вручную.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user'
          AND column_name = 'roles'
          AND data_type = 'json'
    ) THEN
        ALTER TABLE "user"
            ALTER COLUMN roles TYPE jsonb
            USING roles::jsonb;
    END IF;
END
$$;
