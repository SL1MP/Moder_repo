package main

import (
	"log/slog"
	"os"
	"strings"
)

// Уровень логирования из LOG_LEVEL.
//
// Читается здесь, а не в config.Load, намеренно: логгер нужен раньше
// конфигурации — именно им сообщается, что конфигурация невалидна. Класть
// настройку логгера внутрь того, что без логгера не разобрать, значит терять
// первое же сообщение.
//
// Пробел переноса: python-версия LOG_LEVEL применяла, go-версия писала на
// уровне по умолчанию. Совпадение с INFO делало это незаметным — до первой
// попытки включить DEBUG на стенде, где DEBUG как раз и нужен.

// newLogger собирает логгер по LOG_LEVEL.
//
// Неизвестное значение не роняет сервис и не проглатывается: остаётся INFO,
// а о самой опечатке логгер сообщает первой же строкой. Упасть из-за
// написания уровня логирования — несоразмерно; промолчать — значит оставить
// человека гадать, почему DEBUG не включается.
func newLogger(getenv func(string) string) *slog.Logger {
	raw := strings.TrimSpace(getenv("LOG_LEVEL"))
	level, ok := parseLogLevel(raw)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	if !ok && raw != "" {
		logger.Warn("LOG_LEVEL не распознан, оставлен INFO",
			"значение", raw, "допустимые", "DEBUG|INFO|WARNING|WARN|ERROR")
	}
	return logger
}

// parseLogLevel понимает и имена python-версии (WARNING), и имена slog (WARN):
// .env у уже развёрнутых стендов написан по python-версии, и требовать его
// правки ради переименования уровня незачем.
func parseLogLevel(raw string) (slog.Level, bool) {
	switch strings.ToUpper(raw) {
	case "DEBUG":
		return slog.LevelDebug, true
	case "INFO":
		return slog.LevelInfo, true
	case "WARNING", "WARN":
		return slog.LevelWarn, true
	case "ERROR":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}
