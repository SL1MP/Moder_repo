// Package migrations — SQL-миграции схемы, вшитые в бинарник.
//
// Вшиты, а не читаются с диска, намеренно: образ сервиса содержит только
// бинарник (см. Dockerfile), и миграции, лежащие рядом файлами, в него бы не
// доехали. Вшитые — едут вместе с кодом, который их ожидает, и разойтись с
// ним не могут: собрали бинарник — собрали и схему, которую он умеет.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.sql
var files embed.FS

// Migration — одна миграция набора.
type Migration struct {
	// Version — числовой префикс имени файла: «0013». Он же ключ в таблице
	// учёта, поэтому переименование файла задним числом недопустимо.
	Version string
	Name    string
	Up      string
	Down    string
}

// All возвращает миграции по возрастанию версии.
//
// Порядок — не косметика: миграции опираются на состояние, оставленное
// предыдущими, и применённая не в свой черёд падает либо, что хуже, проходит
// и оставляет схему не той, которую ожидает код.
func All() ([]Migration, error) {
	entries, err := fs.Glob(files, "*.up.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)

	out := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		version, name, ok := splitName(entry)
		if !ok {
			return nil, fmt.Errorf(
				"имя файла миграции %q не разбирается: ожидается NNNN_name.up.sql", entry)
		}
		up, err := files.ReadFile(entry)
		if err != nil {
			return nil, err
		}
		migration := Migration{Version: version, Name: name, Up: string(up)}

		// Обратная миграция необязательна, но её отсутствие — то, о чём лучше
		// знать заранее, а не в момент, когда откат понадобился.
		if down, err := files.ReadFile(strings.TrimSuffix(entry, ".up.sql") + ".down.sql"); err == nil {
			migration.Down = string(down)
		}
		out = append(out, migration)
	}
	return out, nil
}

// splitName разбирает «0013_sandbox_step.up.sql» на «0013» и «sandbox_step».
func splitName(entry string) (version, name string, ok bool) {
	base := strings.TrimSuffix(entry, ".up.sql")
	version, name, ok = strings.Cut(base, "_")
	if !ok || version == "" || name == "" {
		return "", "", false
	}
	for _, c := range version {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}
	return version, name, true
}
