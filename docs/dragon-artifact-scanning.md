# Сканирование пакетных артефактов через Dragon

## Граница ответственности

`Moder_repo` остаётся владельцем решения о публикации. Dragon только:

1. получает ссылку на неизменяемый объект в Nexus staging и ожидаемый SHA-256;
2. передаёт работу Runner'ам;
3. Runner скачивает объект, сверяет размер и SHA-256 до запуска контейнера;
4. запускает настроенный pipeline сканеров;
5. хранит исходные отчёты и возвращает нормализованную сводку.

Dragon не получает право записи в целевые репозитории пакетов. На Runner'ах
используется отдельная учётная запись Nexus только с `browse/read` на
`moderation-staging`. Пароль Nexus не передаётся в JSON задания и не хранится
в базе Dragon.

## Почему штатного API Dragon недостаточно

Версия из переданного архива принимает только `POST /api/runs` с Git pipeline,
синхронизирует Git mirror и выдаёт Runner'у `git archive`. В ней отсутствуют:

- запуск по URL пакетного артефакта;
- ожидаемый SHA-256 и подтверждение его проверки Runner'ом;
- корреляционный `external_id` для идемпотентного повтора;
- нормализованный итог нескольких сканеров;
- признак полноты evidence.

Поэтому включать `DRAGON_ENABLED` до обновления Dragon нельзя: `Moder_repo`
намеренно не считает старый ответ достаточным и отправит пакет DevSecOps.

## Контракт Dragon Artifact API

### Создание или получение прогона

`POST /api/artifact-runs`, Bearer PAT:

```json
{
  "pipeline_id": "pl:package-security",
  "external_id": "moderation:item:269:sha256:...64 hex characters...",
  "publish": false,
  "artifact": {
    "manager": "pypi",
    "name": "aenum",
    "version": "2.2.4",
    "filename": "aenum-2.2.4-py3-none-any.whl",
    "url": "http://nexus:8081/repository/moderation-staging/pypi/aenum/2.2.4/aenum-2.2.4-py3-none-any.whl",
    "sha256": "...64 hex characters...",
    "size_bytes": 34821
  }
}
```

Ответ `202` для нового и `200` для уже существующего `external_id`:

```json
{"id":"run-id"}
```

Уникальность `external_id` обязательна. Ключ содержит и `request_item.id`, и
SHA-256: повтор шага для тех же байтов не создаёт второй тяжёлый прогон, но
перезалитый upstream-артефакт никогда не получит evidence от старых байтов.

### Получение результата

`GET /api/runs/{id}/status`:

```json
{
  "id": "run-id",
  "status": "success",
  "done": true,
  "success": true,
  "artifact_verified": true,
  "evidence_complete": true,
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 4,
    "unknown": 0
  },
  "report_urls": [
    "https://dragon.example/api/runs/run-id/reports/trivy"
  ],
  "run_url": "https://dragon.example/runs/run-id"
}
```

`artifact_verified=true` означает, что каждый Runner проверил фактические
байты до запуска сканера. `evidence_complete=true` означает, что все
обязательные Job Run завершились и их результаты вошли в `summary`. Нельзя
выставлять этот признак только потому, что процессы сканеров завершились с
кодом 0: многие инструменты по умолчанию возвращают 0 даже при находках.

## Решение в Moder_repo

- SHA-256 не подтверждён: публикация запрещена, требуется DevSecOps.
- Evidence неполный или обязательный scanner упал: публикация запрещена.
- Есть находки не ниже `DRAGON_MIN_SEVERITY`: требуется DevSecOps.
- Все обязательные evidence получены, digest совпал, блокирующих находок нет:
  шаг пройден.
- Ручное решение DevSecOps может разрешить известные находки, но не заменяет
  отсутствующее сканирование или неподтверждённый SHA-256.

В запросе Moder_repo всегда передаёт `publish=false`: внешняя публикация
отчётов управляется отдельным правилом Dragon и не смешивается с разрешением
пакета в Nexus.

## Настройки Moder_repo

| Переменная | Назначение |
|---|---|
| `DRAGON_ENABLED` | включает обязательный шаг `dragon_scan` |
| `DRAGON_URL` | внутренний URL API Dragon |
| `DRAGON_TOKEN` | PAT Moder_repo в Dragon |
| `DRAGON_PIPELINE_ID` | artifact pipeline со сканерами пакетов |
| `DRAGON_STAGING_URL` | корень raw staging, доступный Runner'ам |
| `DRAGON_POLL_INTERVAL_SECONDS` | интервал polling |
| `DRAGON_TIMEOUT_SECONDS` | общий таймаут одного прогона |
| `DRAGON_MIN_SEVERITY` | `critical`, `high`, `medium` или `low` |

Текущая реализация использует polling и удерживает один worker slot до конца
сканирования. Для целевой нагрузки около 2500 пакетов/час следующим этапом
нужен callback или отдельный poller: пакет переводится в `awaiting_dragon`, а
worker освобождается сразу после создания задания.

## Требования к artifact pipeline Dragon

- SCA/SBOM: Trivy и/или Syft по файлу и безопасно распакованному содержимому;
- malware: ClamAV/YARA или корпоративный движок;
- SAST только для артефактов с исходным кодом; бинарники не должны получать
  фиктивный результат `clean`;
- Docker: сканируется OCI layout/index и все платформенные manifest'ы, а не
  только manifest архитектуры Runner'а;
- распаковка выполняется с лимитами размера, количества файлов и защитой от
  path traversal/symlink escape;
- исходные отчёты хранятся неизменяемо и связываются с SHA-256 артефакта.

