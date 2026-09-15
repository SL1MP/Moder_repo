"""FastAPI-приложение сервиса модерации внешних пакетов."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging, get_logger, new_request_id, request_id_var
from app.core.metrics import http_request_duration, http_requests_total, render_metrics
from app.db.session import get_engine
from app.services.policies import reload_policies
from app.services.watchdog import start_watchdog, stop_watchdog
from app.services.worker_health import worker_status

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Политики (blacklist, справочник лицензий) читаются при старте.
    result = reload_policies()
    log.info("политики загружены", extra={"policies": result})
    if settings.app_env == "prod" and settings.local_auth_enabled:
        log.warning("LOCAL_AUTH_ENABLED=true в prod — fallback-вход должен быть отключён")
    # Сторож очереди: пакет не должен ждать ручного `moderctl run-pending`.
    start_watchdog()
    try:
        yield
    finally:
        stop_watchdog()


app = FastAPI(
    title=settings.app_name,
    description=(
        "Сервис модерации внешних (open-source) пакетов: единственный вход для заведения "
        "пакетов, последовательный конвейер проверок, публикация во внутренний артефактори."
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

if settings.app_env != "prod":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:8080"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

install_error_handlers(app)
app.include_router(api_router)


@app.middleware("http")
async def observability(request: Request, call_next):
    rid = request.headers.get("x-request-id") or new_request_id()
    token = request_id_var.set(rid)
    request.state.request_id = rid
    started = time.perf_counter()
    route = request.url.path
    try:
        response = await call_next(request)
    except Exception:
        # Упавший запрос тоже должен попасть в метрики: иначе 500-е не видны на
        # графиках вовсе. Ответ формирует обработчик исключений выше по стеку.
        _observe(request.method, route, "500", time.perf_counter() - started)
        raise
    finally:
        request_id_var.reset(token)
    _observe(request.method, route, str(response.status_code), time.perf_counter() - started)
    response.headers["x-request-id"] = rid
    return response


def _observe(method: str, route: str, status: str, elapsed: float) -> None:
    http_request_duration.labels(method=method, path=route).observe(elapsed)
    http_requests_total.labels(method=method, path=route, status=status).inc()


@app.get("/health", tags=["Служебные"], summary="Проверка живости и связности")
def health() -> dict[str, object]:
    checks: dict[str, str] = {}
    ok = True
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001 - healthcheck не должен падать
        checks["database"] = f"error: {exc}"
        ok = False
    # Мёртвый worker — это «пакеты не проверяются», и это должно быть видно снаружи.
    # HTTP-код остаётся 200: контейнер API исправен, деградирует обработка очереди.
    worker = worker_status()
    checks["worker"] = "ok" if worker.alive else f"degraded: {worker.detail}"
    if not worker.alive:
        ok = False
    return {"status": "ok" if ok else "degraded", "checks": checks, "env": settings.app_env}


@app.get("/metrics", tags=["Служебные"], summary="Метрики Prometheus")
def metrics() -> Response:
    return Response(content=render_metrics(), media_type="text/plain; version=0.0.4")
