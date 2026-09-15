// Package pipeline — конвейер проверок пакета. Порт backend/app/pipeline/{steps,runner,
// blockers}.py на Go, см. docs/migration-to-go.md. Реализованы шаги 0–3
// (db_check/blacklist/quarantine/license) — они не требуют ещё не перенесённых
// адаптеров (реестры пакетных менеджеров, ArtifactStore, VulnerabilityIndex,
// сканеры содержимого, см. фазы 3 и 5 в docs/migration-to-go.md). Шаги 4–8
// сознательно не заведены — не заглушены "притворным" pass, честно
// отсутствуют, пока нет на чём их выполнять.
package pipeline

// StepOutcome — результат одного шага конвейера.
//
//   - Result — то, что пишется в pipeline_step.result (domain.StepResults).
//   - Stop — останавливает ли шаг конвейер: `true` — дальнейшие шаги не
//     выполняются (аналог "fail, не defer" в Python-версии). Единственное
//     исключение во всём конвейере — шаг "license": его warn не
//     останавливает конвейер (docs/architecture.md, "согласования юристов и
//     DevSecOps идут параллельно"), поэтому Stop=false у него при warn.
//   - ItemStatus/VersionStatus — если не пусты, требуемый статус
//     request_item/package_version после этого шага. Пусто — статус не
//     меняется этим шагом.
type StepOutcome struct {
	Result        string
	Message       string
	Stop          bool
	ItemStatus    string
	VersionStatus string
}
