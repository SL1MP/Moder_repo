-- Уникальность артефакта по паре (версия пакета, имя файла).
--
-- В Python-версии дубли предотвращались только кодом (_get_or_create_artifact
-- делает SELECT, потом INSERT). Одну и ту же версию заказывают в разных
-- заявках, и конвейер по ним идёт параллельно — две проверки «а есть ли уже
-- такой артефакт» способны разойтись между собой и породить две строки на один
-- файл. Дальше шаги сканирования и публикации берут «текущий» артефакт по
-- ORDER BY и могут взять разные: сканировали один объект, опубликовали другой.
--
-- Сначала убираем возможные дубли, оставляя самую раннюю строку: она та, на
-- которую ссылались шаги, успевшие отработать.
DELETE FROM artifact a
USING artifact b
WHERE a.package_version_id = b.package_version_id
  AND a.filename = b.filename
  AND a.id > b.id;

ALTER TABLE artifact
    ADD CONSTRAINT uq_artifact_package_version_id_filename UNIQUE (package_version_id, filename);
