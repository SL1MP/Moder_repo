-- Дерево зависимостей внутри заявки: откуда взялся транзитивный пакет.
--
-- Зачем: до сих пор транзитивная зависимость была в заявке таким же
-- самостоятельным пакетом, как заявленный, и по строке нельзя было сказать,
-- кто её притащил. Юристу и DevSecOps это нужно постоянно: «эта GPL пришла
-- через вот тот пакет» — другой разговор, чем «у нас в заявке GPL».
--
-- parent_item_id ссылается на строку той же таблицы: дерево, а не отдельная
-- сущность связи. ON DELETE SET NULL, а не CASCADE: удаление родителя (чего
-- в обычной жизни не бывает — заявки отменяются, а не удаляются) не должно
-- уносить с собой промодерированные пакеты.
--
-- depth хранится, хотя выводится обходом: по нему делается выборка «покажи
-- только прямые» без рекурсивного запроса, а рекурсия по дереву из сотни
-- узлов на каждый показ карточки — цена на ровном месте.
ALTER TABLE request_item ADD COLUMN IF NOT EXISTS parent_item_id INTEGER
    REFERENCES request_item (id) ON DELETE SET NULL;
ALTER TABLE request_item ADD COLUMN IF NOT EXISTS depth SMALLINT NOT NULL DEFAULT 0;
-- required_range — требование родителя как есть («^4.17.21», «>=2,<4»).
-- Показывается в карточке: по нему видно, почему выбрана именно эта версия.
ALTER TABLE request_item ADD COLUMN IF NOT EXISTS required_range VARCHAR(256);

CREATE INDEX IF NOT EXISTS ix_request_item_parent_item_id ON request_item (parent_item_id);

-- Раскрытие зависимостей на заявке: чем её создавали и что получилось.
-- Флаг include_transitive уже есть (он означал «взять транзитивные записи из
-- файла»), но глубина и итог раскрытия нигде не хранились, а без них нельзя
-- показать «дерево обрезано по пределу» — а молчать об этом нельзя.
ALTER TABLE moderation_request ADD COLUMN IF NOT EXISTS resolve_depth SMALLINT;
ALTER TABLE moderation_request ADD COLUMN IF NOT EXISTS resolve_summary TEXT;
