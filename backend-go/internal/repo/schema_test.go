package repo

import (
	"context"
	"strings"
	"testing"
)

// Сверка схемы проверяется на настоящем Postgres: её работа — это чтение
// системного каталога, и на моке она проверяла бы только сам мок.
//
// Тест написан по живому случаю: кнопка закрытия заявки отвечала 500, потому
// что в базе не была применена миграция со статусом `cancelled`. Снаружи это
// выглядело как случайная ошибка, а не как «схема устарела».

func TestSchemaHasNoGapsOnCurrentSchema(t *testing.T) {
	r, cleanup := mustPool(t)
	defer cleanup()

	gaps, err := r.MissingSchemaObjects(context.Background())
	if err != nil {
		t.Fatalf("сверка схемы: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("на актуальной схеме пробелов быть не должно, получено: %v", gaps)
	}
}

// Пробел находится и называет, чего именно не хватает и что накатить.
//
// Ограничение подменяется на прежний список в транзакции теста — база при
// этом остаётся согласованной: в конце всё возвращается на место.
func TestSchemaGapFoundForStaleConstraint(t *testing.T) {
	r, cleanup := mustPool(t)
	defer cleanup()
	ctx := context.Background()

	const dropNew = `ALTER TABLE request_item DROP CONSTRAINT IF EXISTS request_item_status_check`
	// NOT VALID: в общей тестовой базе уже есть строки со статусом
	// `cancelled` от других тестов, и обычное ограничение на них не
	// налезет. Проверку новых записей NOT VALID не отменяет — именно она
	// здесь и нужна.
	const addOld = `ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
		'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
		'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked',
		'blacklisted', 'failed')) NOT VALID`
	const addNew = `ALTER TABLE request_item ADD CONSTRAINT request_item_status_check CHECK (status IN (
		'queued', 'running', 'quarantined', 'awaiting_legal', 'license_claimed',
		'awaiting_security', 'approved', 'dry_run', 'rejected', 'revoked',
		'blacklisted', 'cancelled', 'failed'))`

	if _, err := r.Pool().Exec(ctx, dropNew); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Pool().Exec(ctx, addOld); err != nil {
		t.Fatal(err)
	}
	// Именно defer, а не t.Cleanup: t.Cleanup выполняется ПОСЛЕ отложенного
	// cleanup(), который закрывает пул, и восстановить ограничение уже нечем.
	defer func() {
		if _, err := r.Pool().Exec(context.Background(), dropNew); err != nil {
			t.Fatalf("восстановление ограничения: %v", err)
		}
		if _, err := r.Pool().Exec(context.Background(), addNew); err != nil {
			t.Fatalf("восстановление ограничения: %v", err)
		}
	}()

	gaps, err := r.MissingSchemaObjects(ctx)
	if err != nil {
		t.Fatalf("сверка схемы: %v", err)
	}
	var found bool
	for _, gap := range gaps {
		if gap.Table == "request_item" && gap.Value == "cancelled" {
			found = true
			if !strings.Contains(gap.Migration, "0011_cancel_request") {
				t.Errorf("пробел не называет миграцию: %s", gap)
			}
		}
	}
	if !found {
		t.Fatalf("пробел по статусу cancelled не найден, получено: %v", gaps)
	}
}

// Пропущенный столбец тоже находится — и это не теория: без
// `resume_from_step` (миграция 0008) молча перестают работать и захват пакета
// воркером, и решение роли, которое ставит пакет в очередь с нужного шага.
func TestSchemaGapFoundForMissingColumn(t *testing.T) {
	r, cleanup := mustPool(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := r.Pool().Exec(ctx,
		`ALTER TABLE request_item DROP COLUMN resume_from_step`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := r.Pool().Exec(context.Background(),
			`ALTER TABLE request_item ADD COLUMN resume_from_step VARCHAR(32)`); err != nil {
			t.Fatalf("восстановление столбца: %v", err)
		}
	}()

	gaps, err := r.MissingSchemaObjects(ctx)
	if err != nil {
		t.Fatalf("сверка схемы: %v", err)
	}
	for _, gap := range gaps {
		if gap.Kind == GapColumn && gap.Column == "resume_from_step" {
			if !strings.Contains(gap.Migration, "0008_queue_resume") {
				t.Errorf("пробел не называет миграцию: %s", gap)
			}
			return
		}
	}
	t.Fatalf("пропущенный столбец не найден, получено: %v", gaps)
}
