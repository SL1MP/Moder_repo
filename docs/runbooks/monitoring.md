# Мониторинг и действия по алертам

Профиль `monitoring` поднимает Prometheus и Grafana. Prometheus опрашивает два процесса:

- `api-go:8000/metrics` — доступность API, состояние очереди и сторож;
- `worker-go:9091/metrics` — фактические результаты и длительность шагов, обращения к внешним системам и возраст OSV.

Порт worker наружу не публикуется. Это служебный endpoint внутри compose-сети.

## ModerationAPIDown

1. `docker compose ps api-go db`.
2. `docker compose logs --since=15m api-go`.
3. `curl -fsS http://localhost:${NGINX_PORT:-8080}/health` и `/ready`.
4. Если `/health` отвечает, а `/ready` нет — проверить PostgreSQL и `DATABASE_URL`.

## ModerationWorkerDown

1. `docker compose ps worker-go`.
2. `docker compose logs --since=15m worker-go`.
3. `docker compose exec -T prometheus wget -qO- http://worker-go:9091/health`.
4. После исправления убедиться, что target `moderation-worker` стал `UP` в Prometheus.

## ModerationWorkerNotProcessing

Endpoint worker жив, но свежие задания не забираются вовремя.

1. Проверить ошибки worker и внешних интеграций.
2. Проверить загрузку CPU/RAM/диска и значение `WORKER_CONCURRENCY`.
3. Посмотреть очередь в `/api/v1/system/status`.
4. Не запускать несколько ручных `worker --once`, пока штатный worker ещё работает.

## ModerationPipelineItemsStuck

Посмотреть текущий шаг зависших пакетов и коррелировать его с графиками «P95 длительности
шагов» и «Внешние интеграции». Если причина устранена, сторож автоматически вернёт брошенную
работу в обработку; ручной перезапуск нужен только для окончательно завершившихся ошибкой
элементов.

## ModerationPipelineFailuresBurst

В Grafana отфильтровать график ошибок по `manager` и `step`. Повторяющийся `download` обычно
указывает на исходный registry, `sandbox_scan` — на песочницу, `publish` — на права или адрес
репозитория артефактори.

## ModerationWatchdogRecoveringItems

Сторож API — страховка, а не штатный исполнитель. Проверить рестарты worker, его загрузку и
достаточность `WORKER_CONCURRENCY`. Частое срабатывание означает, что выделенный worker не
успевает за входным потоком.

## ModerationCircuitBreakerOpen

Найти значение метки `service`, проверить доступность соответствующей интеграции из
`worker-go`, сертификаты CA, proxy/NO_PROXY и credentials. Не отключать circuit breaker: он
защищает очередь от лавины повторных запросов.

## ModerationExternalCallsFailing

Проверить outcomes и сервис на панели «Внешние интеграции», затем логи worker за тот же
интервал. `rate_limited` означает необходимость снизить параллелизм или согласовать лимиты с
владельцем registry; `error`/`failed` требуют разбора HTTP-кода и ответа интеграции.

## ModerationOSVSnapshotMissing

Первичная синхронизация не состоялась либо API ещё не прочитал активный снапшот:

```bash
docker compose run --rm worker-go maintenance --osv-sync --force
docker compose logs --since=30m worker-go
```

## ModerationOSVSnapshotStale

Проверить доступность архивов PyPI/npm, таймаут скачивания и свободное место в `osv-db`.
Устаревший OSV не должен блокировать публикацию автоматически, но увеличивает объём ручных
решений DevSecOps.

