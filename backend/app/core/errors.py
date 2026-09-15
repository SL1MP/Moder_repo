"""Единый формат ошибок: машинный код + человеческое сообщение на русском."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class AppError(Exception):
    """Базовая ошибка приложения."""

    code = "internal_error"
    http_status = 500
    message = "Внутренняя ошибка сервиса"

    def __init__(self, message: str | None = None, **details: Any) -> None:
        self.message = message or self.message
        self.details = details
        super().__init__(self.message)

    def to_payload(self, request_id: str | None = None) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details or None,
                "request_id": request_id,
            }
        }


class NotFoundError(AppError):
    code = "not_found"
    http_status = 404
    message = "Объект не найден"


class ValidationError(AppError):
    code = "validation_error"
    http_status = 422
    message = "Некорректные данные запроса"


class InvalidPackageFormat(AppError):
    code = "invalid_format"
    http_status = 422
    message = "Некорректный формат записи пакета"


class UnknownManagerError(AppError):
    code = "unknown_manager"
    http_status = 422
    message = "Неизвестный пакетный менеджер"


class LimitExceeded(AppError):
    code = "limit_exceeded"
    http_status = 413
    message = "Превышен лимит"


class RateLimited(AppError):
    code = "rate_limited"
    http_status = 429
    message = "Слишком много запросов, попробуйте позже"


class AuthError(AppError):
    code = "unauthorized"
    http_status = 401
    message = "Требуется аутентификация"


class ForbiddenError(AppError):
    code = "forbidden"
    http_status = 403
    message = "Недостаточно прав для этого действия"


class ConflictError(AppError):
    code = "conflict"
    http_status = 409
    message = "Конфликт состояния"


class UpstreamError(AppError):
    code = "upstream_error"
    http_status = 502
    message = "Внешний сервис недоступен"


class CircuitOpenError(UpstreamError):
    code = "circuit_open"
    message = "Обращения к внешнему сервису временно приостановлены (circuit breaker)"


class ConfigurationError(AppError):
    code = "configuration_error"
    http_status = 500
    message = "Ошибка конфигурации сервиса"


_HTTP_CODE_MAP = {
    400: ("bad_request", "Некорректный запрос"),
    401: ("unauthorized", "Требуется аутентификация"),
    403: ("forbidden", "Недостаточно прав для этого действия"),
    404: ("not_found", "Объект не найден"),
    405: ("method_not_allowed", "Метод не поддерживается"),
    409: ("conflict", "Конфликт состояния"),
    413: ("limit_exceeded", "Превышен лимит"),
    429: ("rate_limited", "Слишком много запросов, попробуйте позже"),
}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        rid = getattr(request.state, "request_id", None)
        return JSONResponse(status_code=exc.http_status, content=exc.to_payload(rid))

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        rid = getattr(request.state, "request_id", None)
        err = ValidationError(details=[{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()])
        return JSONResponse(status_code=err.http_status, content=err.to_payload(rid))

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        rid = getattr(request.state, "request_id", None)
        code, msg = _HTTP_CODE_MAP.get(exc.status_code, ("http_error", "Ошибка обработки запроса"))
        detail = exc.detail if isinstance(exc.detail, str) and exc.detail else msg
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {"code": code, "message": detail, "details": None, "request_id": rid}
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        """Необработанное исключение тоже отдаём в едином формате.

        Без этого Starlette возвращает plain-text «Internal Server Error», и клиент
        видит бесполезное «Ошибка запроса (500)» без кода, сообщения и request_id —
        по такому ответу невозможно понять, что сломалось. Тип исключения кладём в
        details, чтобы причина была видна сразу, а полный traceback пишем в лог
        (Starlette после хендлера повторно поднимает исключение, поэтому traceback
        не теряется).
        """
        rid = getattr(request.state, "request_id", None)
        logging.getLogger(__name__).exception(
            "необработанное исключение",
            extra={"path": request.url.path, "method": request.method, "error_type": type(exc).__name__},
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": (
                        "Внутренняя ошибка сервиса. Сообщите администратору request_id — "
                        "по нему в логах есть полный traceback."
                    ),
                    "details": {"error_type": type(exc).__name__},
                    "request_id": rid,
                }
            },
            # ServerErrorMiddleware стоит снаружи middleware наблюдаемости, поэтому
            # заголовок нужно проставить здесь — иначе на 500 его не будет вовсе.
            headers={"x-request-id": rid} if rid else None,
        )
