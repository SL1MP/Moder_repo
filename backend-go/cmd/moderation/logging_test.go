package main

import (
	"log/slog"
	"testing"
)

// LOG_LEVEL применяется — и в написании python-версии тоже.
//
// Проверяется в том числе WARNING: .env уже развёрнутых стендов написан по
// python-версии, где уровень называется так, а slog знает только WARN.
// Непонятое значение молча стало бы INFO, и человек, поднявший уровень, чтобы
// убрать шум из логов, шума бы не убрал.
func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		raw   string
		want  slog.Level
		known bool
	}{
		{"DEBUG", slog.LevelDebug, true},
		{"debug", slog.LevelDebug, true},
		{"INFO", slog.LevelInfo, true},
		{"WARNING", slog.LevelWarn, true},
		{"WARN", slog.LevelWarn, true},
		{"ERROR", slog.LevelError, true},
		// Опечатка не роняет сервис, но и не выдаёт себя за настроенный
		// уровень: вызывающий получает false и пишет об этом в лог.
		{"TRACE", slog.LevelInfo, false},
		{"", slog.LevelInfo, false},
	}
	for _, tc := range cases {
		got, known := parseLogLevel(tc.raw)
		if got != tc.want || known != tc.known {
			t.Errorf("parseLogLevel(%q) = %v, %v; ожидалось %v, %v",
				tc.raw, got, known, tc.want, tc.known)
		}
	}
}

// Логгер собирается и на пустом окружении: сервис обязан писать в лог даже
// тогда, когда не настроено ничего, — иначе о том, что он не настроен, он
// сообщить и не сможет.
func TestNewLoggerWithoutEnv(t *testing.T) {
	if logger := newLogger(func(string) string { return "" }); logger == nil {
		t.Fatal("логгер не собран")
	}
	if logger := newLogger(func(string) string { return "DEBUG" }); logger == nil {
		t.Fatal("логгер не собран при DEBUG")
	}
}
