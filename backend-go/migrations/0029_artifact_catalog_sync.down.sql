DROP TABLE IF EXISTS artifact_catalog_sync_run;
-- BIGINT обратно не сужаем: после импорта в таблице уже могут быть файлы
-- больше 2 ГБ, и безопасного автоматического отката к INTEGER нет.
