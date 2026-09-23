package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"moderation/internal/config"
	"moderation/internal/db"
	"moderation/migrations"
)

// Накатывание схемы.
//
// Отдельная команда, а не автоматический мигратор при старте сервиса: api-go и
// worker-go поднимаются одновременно, и два процесса, накатывающих схему
// наперегонки, оставляют базу в состоянии, из которого её потом достают руками.
// Здесь порядок явный — команда доходит до конца и завершается, а сервисы её
// дожидаются (docker-compose.yml, service_completed_successfully).
//
// Учёт применённого ведётся в отдельной таблице, своей, а не alembic_version:
// наборов миграций два (этот и Alembic python-версии), они идут параллельно и
// про одни и те же таблицы, и складывать их учёт в одно место значит получить
// набор, который считает применённым то, чего не применял.

// migrationsTable — таблица учёта. Имя с суффиксом _go, чтобы её нельзя было
// перепутать с alembic_version при разборе на живой базе.
const migrationsTable = "schema_migrations_go"

func runMigrate(args []string, logger *slog.Logger) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	down := fs.String("down", "", "откатить миграции ПОСЛЕ указанной версии (например, 0012)")
	status := fs.Bool("status", false, "показать, что применено, и выйти")
	baseline := fs.String("baseline", "",
		"отметить миграции по указанную версию включительно как применённые, НЕ выполняя их")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("конфигурация невалидна", "error", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("не удалось подключиться к Postgres", "error", err)
		return 1
	}
	defer pool.Close()

	all, err := migrations.All()
	if err != nil {
		logger.Error("набор миграций не прочитан", "error", err)
		return 1
	}
	if err := ensureMigrationsTable(ctx, pool); err != nil {
		logger.Error("таблица учёта миграций не создана", "error", err)
		return 1
	}
	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		logger.Error("применённые миграции не прочитаны", "error", err)
		return 1
	}

	switch {
	case *status:
		return reportMigrations(all, applied)
	case *baseline != "":
		return baselineMigrations(ctx, pool, all, applied, *baseline, logger)
	case *down != "":
		return rollbackMigrations(ctx, pool, all, applied, *down, logger)
	}
	return applyMigrations(ctx, pool, all, applied, logger)
}

func ensureMigrationsTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS `+migrationsTable+` (
			version    VARCHAR(16) PRIMARY KEY,
			name       VARCHAR(128) NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	return err
}

func appliedVersions(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM `+migrationsTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[string]bool{}
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func applyMigrations(
	ctx context.Context, pool *pgxpool.Pool,
	all []migrations.Migration, applied map[string]bool, logger *slog.Logger,
) int {
	count := 0
	for _, m := range all {
		if applied[m.Version] {
			continue
		}
		// Каждая миграция — в своей транзакции. Одна на весь набор означала бы,
		// что падение последней откатывает и все предыдущие, а это часы работы
		// на большой базе и состояние «ничего не применилось» вместо
		// «применилось до такой-то».
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.Up); err != nil {
				return err
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO `+migrationsTable+` (version, name) VALUES ($1, $2)`,
				m.Version, m.Name)
			return err
		})
		if err != nil {
			logger.Error("миграция не применена", "версия", m.Version, "имя", m.Name,
				"error", err,
				// Подсказка здесь, а не в документации: человек читает лог
				// упавшего контейнера, а не главу про обновление. Самый
				// частый случай — стенд, где схему накатили до появления
				// учёта миграций: старая миграция пытается лечь поверх более
				// новых ДАННЫХ и жалуется на ограничение, хотя запускать её
				// вообще не следовало.
				"подсказка", "если схему этого стенда накатывали вручную до появления учёта, "+
					"отметьте уже применённое: moderation migrate --baseline <версия>, "+
					"затем moderation schema для сверки")
			// Остальные не трогаем: они опираются на эту, и применять их поверх
			// неприменённой значит получить схему, которой нет ни в одном
			// наборе.
			return 1
		}
		logger.Info("миграция применена", "версия", m.Version, "имя", m.Name)
		count++
	}
	if count == 0 {
		logger.Info("схема актуальна, применять нечего", "всего миграций", len(all))
		return 0
	}
	logger.Info("схема обновлена", "применено", count, "всего миграций", len(all))
	return 0
}

// baselineMigrations отмечает миграции как применённые, не выполняя их.
//
// Нужна ровно одному случаю — стенду, на котором схему накатили ДО появления
// учёта: прежняя инструкция предлагала прогнать файлы циклом через psql, и
// такой прогон ничего о себе не записывал. Таблица учёта пуста, а схема при
// этом на уровне двенадцатой миграции.
//
// Без отметки `migrate` начинает с первой, и рано или поздно упирается не в
// схему, а в ДАННЫЕ: миграция 0007 добавляет CHECK на статусы request_item
// без 'cancelled', потому что этот статус появляется только в 0011. На живом
// стенде, где заявки уже закрывали, строки с 'cancelled' есть — и старая
// миграция отказывается накатываться поверх более новых данных, сообщая при
// этом про нарушение ограничения, а не про то, что её вообще не надо было
// запускать.
//
// Поэтому отметка, а не попытка сделать миграции терпимыми к будущим данным:
// миграция описывает схему на свой момент времени, и переписывать историю под
// то, что случилось позже, — способ получить набор, который на чистой базе
// даёт одну схему, а на живой другую.
//
// Схему команда НЕ проверяет: она верит на слово. Поэтому после неё
// обязательна сверка `moderation schema` — она сравнивает базу с тем, что
// пишет код, и назовёт то, чего не хватает.
func baselineMigrations(
	ctx context.Context, pool *pgxpool.Pool,
	all []migrations.Migration, applied map[string]bool, target string, logger *slog.Logger,
) int {
	upTo, known := versionsUpTo(all, target)
	if !known {
		logger.Error("версии нет в наборе миграций", "версия", target,
			"подсказка", "посмотрите `moderation migrate --status`")
		return 1
	}

	var marked, already int
	for _, m := range upTo {
		if applied[m.Version] {
			already++
			continue
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO `+migrationsTable+` (version, name) VALUES ($1, $2)
			 ON CONFLICT (version) DO NOTHING`, m.Version, m.Name); err != nil {
			logger.Error("отметка не записана", "версия", m.Version, "error", err)
			return 1
		}
		logger.Info("отмечена применённой (не выполнялась)", "версия", m.Version, "имя", m.Name)
		marked++
	}

	logger.Info("отметка завершена", "отмечено", marked, "уже были отмечены", already,
		"следующий шаг", "moderation schema — сверить схему с кодом, затем moderation migrate")
	return 0
}

// versionsUpTo — миграции по указанную включительно. Второе значение — есть ли
// такая версия в наборе вообще: отметить схему по несуществующей версии значит
// соврать учёту, и промолчать об опечатке нельзя.
//
// Сравнение строковое: версии — номера одинаковой ширины с ведущими нулями
// (0001…0015), и для них порядок строк совпадает с числовым. Перевод в число
// добавил бы разбор и его ошибку там, где сравнение и так корректно.
func versionsUpTo(all []migrations.Migration, target string) ([]migrations.Migration, bool) {
	known := false
	for _, m := range all {
		if m.Version == target {
			known = true
			break
		}
	}
	if !known {
		return nil, false
	}
	var out []migrations.Migration
	for _, m := range all {
		if m.Version > target {
			break
		}
		out = append(out, m)
	}
	return out, true
}

// rollbackMigrations откатывает всё, что новее указанной версии, от новых к старым.
func rollbackMigrations(
	ctx context.Context, pool *pgxpool.Pool,
	all []migrations.Migration, applied map[string]bool, target string, logger *slog.Logger,
) int {
	known := false
	for _, m := range all {
		if m.Version == target {
			known = true
			break
		}
	}
	if !known && target != "0" {
		logger.Error("версии нет в наборе миграций", "версия", target)
		return 2
	}

	for i := len(all) - 1; i >= 0; i-- {
		m := all[i]
		if m.Version <= target || !applied[m.Version] {
			continue
		}
		if m.Down == "" {
			logger.Error("у миграции нет обратной — откатить нельзя",
				"версия", m.Version, "имя", m.Name)
			return 1
		}
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.Down); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM `+migrationsTable+` WHERE version = $1`, m.Version)
			return err
		})
		if err != nil {
			logger.Error("миграция не откачена", "версия", m.Version, "error", err)
			return 1
		}
		logger.Warn("миграция откачена", "версия", m.Version, "имя", m.Name)
	}
	return 0
}

// reportMigrations печатает состояние набора. Нужен при разборе «почему кнопка
// не работает»: список применённого отвечает на этот вопрос за секунду.
func reportMigrations(all []migrations.Migration, applied map[string]bool) int {
	pending := 0
	for _, m := range all {
		mark := "не применена"
		if applied[m.Version] {
			mark = "применена"
		} else {
			pending++
		}
		fmt.Printf("%-6s %-32s %s\n", m.Version, m.Name, mark)
	}
	if pending > 0 {
		fmt.Printf("\nНе применено миграций: %d. Накатить: moderation migrate\n", pending)
		// Ненулевой код: команду вызывают и из проверок, и «схема неполная»
		// обязано быть отличимо от «всё на месте» без разбора вывода.
		return 1
	}
	fmt.Printf("\nВсе %d миграций применены.\n", len(all))
	return 0
}
