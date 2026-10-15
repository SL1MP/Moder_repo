-- Docker допускает тег длиной до 128 символов. В каталоге версия хранится
-- вместе с digest: <tag>@sha256:<64 hex>, поэтому прежних VARCHAR(128)
-- недостаточно даже для корректной ссылки на существующий образ.
ALTER TABLE package_version
    ALTER COLUMN version TYPE VARCHAR(512),
    ALTER COLUMN raw_version TYPE VARCHAR(512);

-- То же значение переносится в заявку. Размеры связанных полей должны
-- совпадать, иначе пакет можно импортировать из артефактори, но нельзя
-- запросить через обычный конвейер.
ALTER TABLE request_item
    ALTER COLUMN requested_version TYPE VARCHAR(512);
