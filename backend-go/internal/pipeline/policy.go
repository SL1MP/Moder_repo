package pipeline

import "moderation/internal/policy"

// Политики конвейера — blacklist и справочник лицензий. Сами правила и их
// чтение из файлов живут в internal/policy; здесь только интерфейсы, через
// которые их видят шаги.
//
// Отдельных «in-memory» реализаций тут больше нет: они дублировали разбор
// правил (сверку версий и glob по имени) и разошлись бы с настоящей при первой
// же правке — а расхождение здесь означает, что запрещённый пакет проходит.

// BlacklistPolicy — источник правил запрета.
type BlacklistPolicy interface {
	// Find — первое подходящее правило, nil если пакет не запрещён.
	Find(manager, name, version string) *policy.Rule
	// Failed — правила не удалось прочитать. Это НЕ то же самое, что пустой
	// список: во втором случае запрещать нечего, в первом мы не знаем, что
	// запрещено.
	Failed() bool
}

// LicensePolicy — справочник разрешённых лицензий.
type LicensePolicy interface {
	IsAllowed(spdxID string) bool
	Failed() bool
}
