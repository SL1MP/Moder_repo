package repo

import (
	"context"
	"fmt"
	"strings"
)

// Сверка схемы базы с тем, что пишет код.
//
// Зачем это есть. Допустимые значения статусов и результатов шагов заданы
// дважды: в коде (internal/domain/enums.go) и в CHECK-ограничениях базы,
// которые ставит миграция. Разойтись они могут запросто — миграцию забыли
// накатить, накатили не тот набор из двух (alembic/golang-migrate), откатили
// один и не откатили другой. Снаружи расхождение выглядит не как «схема
// устарела», а как случайная ошибка при нажатии кнопки: код пытается записать
// значение, база отвергает его с CheckViolation, пользователь видит
// «Заявка не закрыта» и идти ему с этим некуда.
//
// Ровно так это и случилось: кнопка закрытия заявки отвечала 500, потому что
// в базе не было применено ограничение со статусом `cancelled`.
//
// Поэтому сервис сверяет это сам при старте и говорит, какой миграции не
// хватает, ДО того как кто-то нажмёт кнопку.
//
// Проверка текстовая — по определению ограничения (pg_get_constraintdef).
// Пробовать записать значение по-настоящему было бы точнее, но означало бы
// трогать живые строки ради самопроверки.

// SchemaGap — значение, которое код пишет, а база не разрешает.
type SchemaGap struct {
	Table      string
	Column     string
	Value      string
	Constraint string
	// Migration — что накатить. Названы оба набора: боевую базу может
	// создавать любой из них.
	Migration string
}

func (g SchemaGap) String() string {
	return fmt.Sprintf("%s.%s не разрешает значение %q (ограничение %s) — накатите %s",
		g.Table, g.Column, g.Value, g.Constraint, g.Migration)
}

// requiredCheckValues — значения, без которых код не работает, и миграции,
// которые их добавляют.
//
// Список пополняется вместе с каждой миграцией, меняющей CHECK: это и есть
// то место, где новая миграция становится обязательной, а не «хорошо бы».
var requiredCheckValues = []struct {
	table, column string
	values        []string
	migration     string
}{
	{
		table: "pipeline_step", column: "result", values: []string{"info"},
		migration: "backend-go/migrations/0010_sast_advisory.up.sql " +
			"(или alembic 0005_sast_advisory)",
	},
	{
		table: "request_item", column: "status", values: []string{"dry_run", "cancelled"},
		migration: "backend-go/migrations/0007_dry_run_status.up.sql и " +
			"0011_cancel_request.up.sql (или alembic 0006_cancel_request)",
	},
	{
		table: "moderation_request", column: "status", values: []string{"dry_run", "cancelled"},
		migration: "backend-go/migrations/0009_request_dry_run.up.sql и " +
			"0011_cancel_request.up.sql (или alembic 0006_cancel_request)",
	},
}

// MissingCheckValues возвращает значения, которые код пишет, а база отвергнет.
//
// Пустой результат — схема согласована. Ошибка возвращается только если не
// удалось прочитать сами ограничения: тогда о согласованности ничего не
// известно, и делать вид, что всё хорошо, нельзя.
func (r *Repo) MissingCheckValues(ctx context.Context) ([]SchemaGap, error) {
	var gaps []SchemaGap
	for _, req := range requiredCheckValues {
		defs, err := r.checkDefs(ctx, req.table, req.column)
		if err != nil {
			return nil, err
		}
		if len(defs) == 0 {
			// Ограничения нет вовсе — база ничего не запрещает. Это не пробел
			// в схеме: код запишет что хотел.
			continue
		}
		for _, value := range req.values {
			for name, def := range defs {
				// Значение должно быть разрешено КАЖДЫМ ограничением на этот
				// столбец. Их может оказаться два: миграции двух наборов
				// называют ограничение по-разному, и если накатить один
				// набор поверх базы, созданной другим, старое ограничение со
				// прежним списком осталось бы рядом и запрещало новое
				// значение молча.
				if !strings.Contains(def, "'"+value+"'") {
					gaps = append(gaps, SchemaGap{
						Table: req.table, Column: req.column, Value: value,
						Constraint: name, Migration: req.migration,
					})
				}
			}
		}
	}
	return gaps, nil
}

// checkDefs — определения CHECK-ограничений таблицы, упоминающих столбец.
func (r *Repo) checkDefs(ctx context.Context, table, column string) (map[string]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT conname, pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = $1::regclass AND contype = 'c'
	`, table)
	if err != nil {
		return nil, fmt.Errorf("чтение CHECK-ограничений таблицы %s: %w", table, err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			return nil, err
		}
		// Ограничения на другие столбцы той же таблицы нас не касаются.
		if strings.Contains(def, column) {
			out[name] = def
		}
	}
	return out, rows.Err()
}
