"""Метрики Prometheus, отдаются на /metrics."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

REGISTRY = CollectorRegistry(auto_describe=True)

http_requests_total = Counter(
    "moderation_http_requests_total",
    "Число HTTP-запросов",
    ["method", "path", "status"],
    registry=REGISTRY,
)
http_request_duration = Histogram(
    "moderation_http_request_duration_seconds",
    "Длительность обработки HTTP-запроса",
    ["method", "path"],
    registry=REGISTRY,
)
pipeline_step_total = Counter(
    "moderation_pipeline_step_total",
    "Результаты шагов конвейера",
    ["step", "result", "manager"],
    registry=REGISTRY,
)
pipeline_duration = Histogram(
    "moderation_pipeline_step_duration_seconds",
    "Длительность шага конвейера",
    ["step"],
    registry=REGISTRY,
)
external_call_total = Counter(
    "moderation_external_call_total",
    "Вызовы внешних сервисов",
    ["service", "outcome"],
    registry=REGISTRY,
)
circuit_state = Gauge(
    "moderation_circuit_state",
    "Состояние circuit breaker (0=closed, 1=open, 2=half-open)",
    ["service"],
    registry=REGISTRY,
)
worker_alive = Gauge(
    "moderation_worker_alive",
    "Есть ли живой Celery-worker, разбирающий очередь (1/0)",
    registry=REGISTRY,
)
pipeline_stuck_items = Gauge(
    "moderation_pipeline_stuck_items",
    "Пакеты, висящие в очереди дольше PIPELINE_STUCK_AFTER_SECONDS",
    registry=REGISTRY,
)
watchdog_recovered_total = Counter(
    "moderation_watchdog_recovered_total",
    "Пакеты, подхваченные сторожем очереди",
    ["mode"],
    registry=REGISTRY,
)
osv_index_age_days = Gauge(
    "moderation_osv_index_age_days",
    "Возраст активного снапшота OSV в днях",
    registry=REGISTRY,
)


def render_metrics() -> bytes:
    return generate_latest(REGISTRY)
