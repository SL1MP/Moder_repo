package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/internal/repo"
)

// Команда `moderation schema` — сверка схемы базы с тем, что пишет код.
//
// Нужна, когда «кнопка не работает»: код пытается записать значение или
// прочитать столбец, которых в схеме нет, база отвергает запрос, а снаружи
// это выглядит как случайная ошибка интерфейса. Команда отвечает на вопрос
// «чего не хватает и что накатить» одним запуском, без чтения логов:
//
//	docker compose run --rm api-go schema
//
// Код возврата 1 при пробелах — чтобы команду можно было поставить в проверку
// перед деплоем.
func runSchemaCheck(args []string, logger *slog.Logger) int {
	fs := flag.NewFlagSet("schema", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("конфигурация невалидна", "error", err)
		return 1
	}

	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("не удалось подключиться к Postgres", "error", err)
		return 1
	}
	defer pool.Close()

	gaps, err := repo.New(pool).MissingSchemaObjects(ctx)
	if err != nil {
		logger.Error("схему сверить не удалось", "error", err)
		return 1
	}
	// Отчёт печатается в stdout, а не в лог: команду читает человек.
	if len(gaps) == 0 {
		fmt.Println("Схема базы согласована с кодом: пробелов нет.")
		return 0
	}

	fmt.Printf("СХЕМА БАЗЫ УСТАРЕЛА: пробелов — %d.\n\n", len(gaps))
	for _, gap := range gaps {
		fmt.Printf("  · %s\n", gap)
	}
	fmt.Println("\nПока миграции не накатят, часть действий будет отвечать ошибкой:")
	fmt.Println("  · закрытие заявки (статус cancelled);")
	fmt.Println("  · решения ролей и перезапуск (очередь конвейера);")
	fmt.Println("  · запись шага SAST (результат info).")
	return 1
}
