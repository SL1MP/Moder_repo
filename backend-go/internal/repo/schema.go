package repo

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"moderation/internal/domain"
)

// Сверка схемы базы с тем, что пишет код.
//
// Зачем это есть. Допустимые значения статусов и результатов шагов заданы
// дважды: в коде (internal/domain/enums.go) и в CHECK-ограничениях базы,
// которые ставит миграция. Столбцы и таблицы, добавленные поздними
// миграциями, — тоже условие работы кода. Разойтись это может запросто:
// миграцию забыли накатить, накатили не тот набор из двух
// (alembic/golang-migrate), откатили один и не откатили другой.
//
// Снаружи расхождение выглядит не как «схема устарела», а как случайная
// ошибка при нажатии кнопки: код пытается записать значение или прочитать
// столбец, база отвергает запрос, пользователь видит «Заявка не закрыта» или
// «Решение не применено» — и идти ему с этим некуда.
//
// Ровно так и случилось на живом стенде: сначала кнопка закрытия заявки, потом
// решение DevSecOps. Поэтому сервис сверяет схему сам при старте и говорит,
// чего не хватает, ДО того как кто-то нажмёт кнопку; та же сверка доступна
// командой `moderation schema`.
//
// Проверка значений текстовая — по определению ограничения
// (pg_get_constraintdef). Пробовать записать значение по-настоящему было бы
// точнее, но означало бы трогать живые строки ради самопроверки.

// GapKind — чего именно не хватает.
type GapKind string

const (
	GapValue  GapKind = "значение"
	GapColumn GapKind = "столбец"
	GapTable  GapKind = "таблица"
)

// SchemaGap — то, чего код ждёт от базы, а в базе этого нет.
type SchemaGap struct {
	Kind   GapKind
	Table  string
	Column string
	Value  string
	// Constraint — ограничение, которое отвергает значение (для GapValue).
	Constraint string
	// Migration — что накатить. Названы оба набора: боевую базу может
	// создавать любой из них.
	Migration string
}

func (g SchemaGap) String() string {
	switch g.Kind {
	case GapTable:
		return fmt.Sprintf("нет таблицы %s — накатите %s", g.Table, g.Migration)
	case GapColumn:
		return fmt.Sprintf("нет столбца %s.%s — накатите %s", g.Table, g.Column, g.Migration)
	default:
		return fmt.Sprintf("%s.%s не разрешает значение %q (ограничение %s) — накатите %s",
			g.Table, g.Column, g.Value, g.Constraint, g.Migration)
	}
}

// checkedValues — столбцы с CHECK-ограничением и списки значений, которыми
// пользуется код. Источник значений — те же константы, что использует сам код
// (internal/domain), поэтому список не может разойтись с ним: новое значение
// появляется в enum'е и сразу попадает в сверку.
var checkedValues = []struct {
	table, column string
	values        []string
}{
	{"package", "manager", domain.ManagerCodes},
	{"package_version", "status", domain.VersionStatuses},
	{"moderation_request", "status", domain.RequestStatuses},
	{"moderation_request", "source", domain.RequestSources},
	{"moderation_request", "manager", domain.ManagerCodes},
	{"request_item", "status", domain.ItemStatuses},
	{"request_item", "dependency_kind", domain.DependencyKinds},
	{"pipeline_step", "step_code", domain.StepCodes},
	{"pipeline_step", "result", domain.StepResults},
	{"artifact", "status", domain.ArtifactStatuses},
	{"license_claim", "status", domain.ClaimStatuses},
}

// valueMigrations — какая миграция добавила значение. Нужны только поздние:
// всё из начальной схемы приезжает вместе с базой.
var valueMigrations = map[string]string{
	"info":      "backend-go/migrations/0010_sast_advisory (или alembic 0005_sast_advisory)",
	"running":   "backend-go/migrations/0019_pipeline_step_running",
	"cancelled": "backend-go/migrations/0011_cancel_request (или alembic 0006_cancel_request)",
	"dry_run": "backend-go/migrations/0007_dry_run_status и 0009_request_dry_run " +
		"(или alembic 0006_cancel_request)",
	"banner_scan": "backend-go/migrations/0004_step_codes_content_scans (или alembic 0004)",
	"sast_scan":   "backend-go/migrations/0004_step_codes_content_scans (или alembic 0004)",
	// Шаг песочницы вместо снятых сканеров содержимого.
	"sandbox_scan": "backend-go/migrations/0013_sandbox_step",
	// Менеджеры сверх четырёх, перенесённых прототипом.
	"conan":     migrationManagers,
	"docker":    migrationManagers,
	"luarocks":  migrationManagers,
	"maven":     migrationManagers,
	"php":       migrationManagers,
	"terraform": migrationManagers,
	"git":       migrationManagers,
	"files":     migrationManagers,
}

const migrationManagers = "backend-go/migrations/0014_package_managers"

const migrationsGeneric = "пропущенные миграции из backend-go/migrations (или alembic)"

// requiredColumns — столбцы, без которых код не работает. Появились поздними
// миграциями, и именно их отсутствие ломает то, что снаружи выглядит как
// «кнопка не работает».
var requiredColumns = []struct {
	table, column, migration string
}{
	// Очередь и возобновление конвейера: без них не работают ни захват пакета
	// воркером, ни решение роли (оно ставит пакет в очередь с нужного шага).
	{"request_item", "resume_from_step", "backend-go/migrations/0008_queue_resume"},
	{"request_item", "attempts", "backend-go/migrations/0008_queue_resume"},
	// Решение DevSecOps записывается на версии пакета.
	{"package_version", "security_override_at",
		"backend-go/migrations/0002_security_override_on_package_version (или alembic 0002)"},
	{"package_version", "security_override_by_id",
		"backend-go/migrations/0002_security_override_on_package_version (или alembic 0002)"},
	{"package_version", "security_override_comment",
		"backend-go/migrations/0002_security_override_on_package_version (или alembic 0002)"},
	// Дерево зависимостей внутри заявки: без этих столбцов не создаётся ни
	// один пакет заявки — вставка идёт с ними всегда.
	{"request_item", "parent_item_id",
		"backend-go/migrations/0012_dependency_tree (или alembic 0007)"},
	{"request_item", "depth", "backend-go/migrations/0012_dependency_tree (или alembic 0007)"},
	{"request_item", "required_range",
		"backend-go/migrations/0012_dependency_tree (или alembic 0007)"},
	{"moderation_request", "resolve_depth",
		"backend-go/migrations/0012_dependency_tree (или alembic 0007)"},
	{"moderation_request", "resolve_summary",
		"backend-go/migrations/0012_dependency_tree (или alembic 0007)"},
	// Промежуточная зона вместо S3: столбцы переименованы, а не добавлены
	// (s3_bucket -> staging_repo и далее). Проверять обязательно именно их:
	// пока миграция не накатана, в базе лежат прежние имена, код пишет в
	// новые, и первым это ловит не сервис, а шаг скачивания — уже после
	// похода в реестр.
	//
	// Без этих строк сверка молчала бы о непринятой 0015: остальные её
	// проверки смотрят на CHECK-ограничения и таблицы, а переименование не
	// меняет ни того, ни другого.
	{"artifact", "staging_repo", "backend-go/migrations/0015_staging_columns"},
	{"artifact", "staging_path", "backend-go/migrations/0015_staging_columns"},
	{"artifact", "staged_at", "backend-go/migrations/0015_staging_columns"},
	{"artifact", "staging_cleared_at", "backend-go/migrations/0015_staging_columns"},
	{"scan_report", "repo", "backend-go/migrations/0015_staging_columns"},
}

// requiredTables — таблицы поздних миграций.
var requiredTables = []struct{ table, migration string }{
	{"code_finding", "backend-go/migrations/0003_code_findings (или alembic 0003)"},
	{"scan_report", "backend-go/migrations/0005_scan_reports"},
}

// MissingSchemaObjects возвращает всё, чего код ждёт от базы, а в базе нет.
//
// Пустой результат — схема согласована. Ошибка возвращается только если не
// удалось прочитать системный каталог: тогда о согласованности ничего не
// известно, и делать вид, что всё хорошо, нельзя.
func (r *Repo) MissingSchemaObjects(ctx context.Context) ([]SchemaGap, error) {
	var gaps []SchemaGap

	for _, req := range requiredTables {
		exists, err := r.tableExists(ctx, req.table)
		if err != nil {
			return nil, err
		}
		if !exists {
			gaps = append(gaps, SchemaGap{
				Kind: GapTable, Table: req.table, Migration: req.migration,
			})
		}
	}

	for _, req := range requiredColumns {
		exists, err := r.columnExists(ctx, req.table, req.column)
		if err != nil {
			return nil, err
		}
		if !exists {
			gaps = append(gaps, SchemaGap{
				Kind: GapColumn, Table: req.table, Column: req.column, Migration: req.migration,
			})
		}
	}

	valueGaps, err := r.missingCheckValues(ctx)
	if err != nil {
		return nil, err
	}
	return append(gaps, valueGaps...), nil
}

func (r *Repo) missingCheckValues(ctx context.Context) ([]SchemaGap, error) {
	var gaps []SchemaGap
	for _, req := range checkedValues {
		exists, err := r.tableExists(ctx, req.table)
		if err != nil {
			return nil, err
		}
		if !exists {
			// Отсутствие таблицы — отдельный пробел (см. requiredTables);
			// здесь молчим, чтобы не сыпать одним и тем же дважды.
			continue
		}
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
			for _, name := range sortedKeys(defs) {
				// Значение должно быть разрешено КАЖДЫМ ограничением на этот
				// столбец. Их может оказаться два: миграции двух наборов
				// называют ограничение по-разному, и если накатить один набор
				// поверх базы, созданной другим, старое ограничение со прежним
				// списком осталось бы рядом и запрещало новое значение молча.
				if strings.Contains(defs[name], "'"+value+"'") {
					continue
				}
				migration := valueMigrations[value]
				if migration == "" {
					migration = migrationsGeneric
				}
				gaps = append(gaps, SchemaGap{
					Kind: GapValue, Table: req.table, Column: req.column,
					Value: value, Constraint: name, Migration: migration,
				})
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

func (r *Repo) tableExists(ctx context.Context, table string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("проверка таблицы %s: %w", table, err)
	}
	return exists, nil
}

func (r *Repo) columnExists(ctx context.Context, table, column string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
		)
	`, table, column).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("проверка столбца %s.%s: %w", table, column, err)
	}
	return exists, nil
}

// sortedKeys — порядок обхода ограничений фиксирован: в логе и в выводе
// команды одна и та же схема должна давать один и тот же текст.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
