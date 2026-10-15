# Жёсткий тест Maven: 35 пакетов

Набор проверяет три независимых участка: извлечение лицензии из POM/parent POM,
скачивание многофайлового релиза и публикацию только разрешённых файлов.

## Что входит

- обычные JAR/POM с Apache-2.0, MIT, BSD, PostgreSQL и EPL;
- неоднозначные/копилефтные метаданные: H2, Hibernate и MySQL Connector/J;
- Kotlin 2.2.21 с большим числом `*-gradle*.jar` и `.module`;
- Android `appcompat` с `.aar`;
- Kotlin/Native с `.klib`;
- `protoc` с платформенными `protoc-*.exe`;
- дистрибутив Maven с `.zip`.

`pom.xml` содержит ровно 35 прямых зависимостей. С включённой галочкой
транзитивных зависимостей заявка будет намного больше — это отдельный стресс-
режим, а не ошибка набора.

## Запуск через web

1. Выберите менеджер Maven.
2. Выберите добавление через файл зависимостей.
3. Загрузите `loadtest/maven-35/pom.xml`.
4. Первый прогон сделайте без транзитивных зависимостей: ожидается 35 позиций.
5. Второй прогон сделайте с транзитивными зависимостями для проверки resolver.

`packages.txt` можно вставить в текстовое поле, а `requests.json` использовать
в нагрузочном клиенте. `expected-licenses.tsv` — контрольная таблица семейств
лицензий. Для H2, Hibernate, PostgreSQL и MySQL допустимо несколько честных
представлений: важны сохранённый `license_raw`, корректный SPDX там, где он
однозначен, и передача неоднозначного случая юристу вместо молчаливого допуска.

## Проверка лицензий в PostgreSQL

Подставьте номер созданной заявки вместо `REQUEST_ID`:

```bash
REQUEST_ID=123

sudo docker compose exec -T db sh -lc \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v request_id='"$REQUEST_ID"' -P pager=off -c "
SELECT
    ri.requested_name,
    ri.requested_version,
    pv.license_spdx,
    pv.license_raw,
    pv.license_source,
    ps.result AS license_result,
    ps.message AS license_message
FROM request_item ri
JOIN package_version pv ON pv.id = ri.package_version_id
LEFT JOIN pipeline_step ps
       ON ps.request_item_id = ri.id AND ps.step_code = '\''license'\''
WHERE ri.request_id = :request_id
ORDER BY ri.dependency_kind, ri.requested_name, ri.requested_version;
"'
```

Проверка должна показать:

- распознанный SPDX для обычных лицензий;
- источник `registry`;
- отдельное решение для составных/копилефтных лицензий;
- отсутствие пустого SPDX у Apache/MIT/EPL/BSD-пакетов.

## Проверка опубликованных файлов

```bash
export JFROG_URL='https://repo.example/artifactory'
export JFROG_REPO='maven-moderated'
export JFROG_TOKEN='...'

bash loadtest/maven-35/verify-artifactory.sh
```

Скрипт требует `curl` и `jq`. Он завершится с ошибкой, если:

- опубликованы `-sources.jar`, `-javadoc.jar`, `.md5`, `.sha1`, `.sha256`,
  `.sha512` или `.asc`;
- опубликован файл вне белого списка `.zip/.jar/.pom/.aar/.klib/.module` и
  `protoc-*.exe`;
- отсутствует POM;
- для специальных тестовых пакетов не найдены Gradle JAR, AAR, KLIB, ZIP или
  платформенные `protoc-*.exe`.

Пакеты, остановленные лицензией до скачивания/публикации, естественно ещё не
будут найдены этим скриптом. Сначала зафиксируйте результат лицензии и примите
решение юриста, затем проверяйте их файлы.
