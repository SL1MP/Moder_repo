package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Единый формат ошибки — тот же, что у python-версии
// (backend/app/core/errors.py): машинный код + человеческое сообщение на
// русском. Формат обязан совпадать байт в байт: nginx раздаёт часть путей
// Go-сервису, часть — python-версии, а разбирает ответы один и тот же
// frontend/src/lib/api.ts, который читает error.code и error.message.
type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Details   any    `json:"details"`
	RequestID string `json:"request_id"`
}

// Error — ошибка запроса с машинным кодом и HTTP-статусом.
type Error struct {
	Code    string
	Status  int
	Message string
	Details any
	// cause — техническая причина. Наружу НЕ уходит: в ней бывают адреса и
	// ключи внутренних систем. Уходит в лог рядом с request_id, по которому
	// ответ и запись в логе связываются.
	cause error
}

func (e *Error) Error() string { return e.Message }

func (e *Error) Unwrap() error { return e.cause }

// Because привязывает к ответу техническую причину для лога.
func (e *Error) Because(err error) *Error {
	e.cause = err
	return e
}

// Конструкторы под коды python-версии. Отдельные функции, а не константы:
// сообщение почти всегда уточняется под конкретный случай, а код — нет.
func errUnauthorized(message string) *Error {
	return &Error{Code: "unauthorized", Status: http.StatusUnauthorized, Message: message}
}

func errForbidden(message string) *Error {
	return &Error{Code: "forbidden", Status: http.StatusForbidden, Message: message}
}

func errNotFound(message string) *Error {
	return &Error{Code: "not_found", Status: http.StatusNotFound, Message: message}
}

func errValidation(message string) *Error {
	return &Error{Code: "validation_error", Status: http.StatusUnprocessableEntity, Message: message}
}

func errInternal(message string) *Error {
	return &Error{Code: "internal_error", Status: http.StatusInternalServerError, Message: message}
}

func errBadRequest(message string) *Error {
	return &Error{Code: "bad_request", Status: http.StatusBadRequest, Message: message}
}

func errUpstream(message string) *Error {
	return &Error{Code: "upstream_error", Status: http.StatusBadGateway, Message: message}
}

// writeError отдаёт ошибку в едином формате. Любая ошибка, не являющаяся
// *Error, — это 500: наружу уходит общий текст, подробности остаются в логе.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		apiErr = errInternal(
			"Внутренняя ошибка сервиса. Сообщите администратору request_id — по нему в логах есть подробности").
			Because(err)
	}
	if apiErr.cause != nil {
		defaultLogger.Printf("[%s] %s %s: %s: %v",
			RequestID(r.Context()), r.Method, r.URL.Path, apiErr.Message, apiErr.cause)
	}
	writeJSON(w, apiErr.Status, errorBody{Error: errorPayload{
		Code:      apiErr.Code,
		Message:   apiErr.Message,
		Details:   apiErr.Details,
		RequestID: RequestID(r.Context()),
	}})
}

// --------------------------------------------------------------------------- request_id

type requestIDKey struct{}

// RequestID — идентификатор запроса из контекста. Пустая строка, если
// middleware не подключено (в тестах отдельных обработчиков).
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// withRequestID проставляет идентификатор запроса так же, как python-версия:
// берёт из заголовка x-request-id, иначе генерирует hex uuid4, и возвращает
// тем же заголовком. Формат совпадает намеренно — запрос может пройти через
// обе версии сервиса, и по одному идентификатору должны находиться обе
// половины следа.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("x-request-id")
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set("x-request-id", rid)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, rid)))
	})
}

func newRequestID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "0000"
	}
	// Версия и вариант UUID4 — чтобы идентификатор был не отличим от того,
	// что пишет python-версия (uuid.uuid4().hex).
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return hex.EncodeToString(buf[:])
}

// writeJSON — JSON-ответ с явным статусом.
//
// SetEscapeHTML(false) обязателен: иначе encoding/json экранирует кириллицу и
// сообщения уезжают в АБ — нечитаемо и в ответе, и в
// логе (см. handoff, п. 8.4).
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		defaultLogger.Printf("не удалось записать ответ: %v", err)
	}
}

// contextWithTimeout — фон с ограничением по времени. Отдельной функцией,
// чтобы в обработчиках было видно: контекст берётся НЕ из запроса.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func formatInt(v int64) string { return strconv.FormatInt(v, 10) }
