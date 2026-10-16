-- Первые версии синхронизации считали первый сегмент native JFrog Conan
-- layout именем рецепта. Фактический путь имеет вид
-- owner/name/version/channel/revision/..., поэтому в каталоге появлялись
-- ложные координаты test_product/boost и _/zlib.
--
-- Удаляем только автоматически импортированные версии, на которые не
-- ссылается ни одна заявка. Физические файлы в артефактори не затрагиваются:
-- следующий ручной обход создаст корректные name/version и ссылки.
WITH malformed AS (
    SELECT DISTINCT pv.id
    FROM package_version pv
    JOIN package p ON p.id = pv.package_id
    JOIN artifact a ON a.package_version_id = pv.id
    WHERE p.manager = 'conan'
      AND pv.license_source = 'artifact_catalog'
      AND cardinality(string_to_array(trim(BOTH '/' FROM a.filename), '/')) >= 5
      AND (
          lower(p.name) <> lower(split_part(trim(BOTH '/' FROM a.filename), '/', 2))
          OR pv.raw_version <> split_part(trim(BOTH '/' FROM a.filename), '/', 3)
      )
      AND NOT EXISTS (
          SELECT 1 FROM request_item ri WHERE ri.package_version_id = pv.id
      )
)
DELETE FROM package_version pv
USING malformed
WHERE pv.id = malformed.id;

DELETE FROM package p
WHERE p.manager = 'conan'
  AND NOT EXISTS (
      SELECT 1 FROM package_version pv WHERE pv.package_id = p.id
  );
