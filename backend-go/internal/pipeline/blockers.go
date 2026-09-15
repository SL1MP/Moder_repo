package pipeline

import "moderation/internal/domain"

// OpenResults — какие значения pipeline_step.result считаются "блокировка не
// снята" для данного шага. Порт OPEN_RESULTS (app/pipeline/blockers.py).
// vuln_scan (шаг 5) намеренно не заведён — ещё не реализован (см. steps.go).
var OpenResults = map[string][]string{
	"quarantine": {"warn"},
	"license":    {"warn"},
}

// PendingBlockers — какие шаги из уже сохранённой истории пакета всё ещё не
// закрыты, в приоритетном порядке (порт pending_blockers, PublishStep будет
// проверять этот список первым делом — фаза с шагом 8, ещё не реализована).
func PendingBlockers(steps []domain.PipelineStep) []string {
	byCode := make(map[string]string, len(steps))
	for _, s := range steps {
		byCode[s.StepCode] = s.Result
	}
	var open []string
	// Порядок как в Python: quarantine, license — приоритет более ранних
	// шагов конвейера первым.
	for _, code := range []string{"quarantine", "license"} {
		result, ok := byCode[code]
		if !ok {
			continue
		}
		for _, openResult := range OpenResults[code] {
			if result == openResult {
				open = append(open, code)
				break
			}
		}
	}
	return open
}

// IsBlockedBy — есть ли открытая блокировка по конкретному шагу.
func IsBlockedBy(steps []domain.PipelineStep, code string) bool {
	for _, s := range PendingBlockers(steps) {
		if s == code {
			return true
		}
	}
	return false
}
