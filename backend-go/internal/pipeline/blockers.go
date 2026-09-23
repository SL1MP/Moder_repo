package pipeline

import "moderation/internal/domain"

// Непогашенные согласования пакета. Порт backend/app/pipeline/blockers.py.
//
// Состояние блокировки не хранится отдельной сущностью: шаг считается
// непогашенным, пока строка pipeline_step имеет результат из OpenResults.
// Снятие — отметка шага пройденным. Так состояние остаётся в одном месте и
// сразу видно в карточке заявки.
//
// ВАЖНО: таблицы ниже — единственный источник правды по тому, чьё решение
// требуется. Дублировать их в другом модуле нельзя: в Python-версии это уже
// один раз сделали и получили KeyError: 'banner_scan' в бою.
//
// Снятых шагов (domain.RetiredStepCodes) здесь нет и быть не должно: в таблицах
// перечислено, чьё решение ждёт пакет ПРЯМО СЕЙЧАС, а шаг, который больше не
// выполняется, ждать ничего не может. Старые строки banner_scan с результатом
// warn перевела в info миграция 0013 — иначе пакеты, остановленные снятым
// шагом, ждали бы решения, которого никто уже не примет (ровно та же история,
// что с sast_scan в 0010).

// BlockerPriority — порядок по «блокирующей силе». Статус у пакета один, а
// ждать он может двух решений сразу; показываем самое блокирующее, чтобы
// статус не «слабел» при действиях по менее важному шагу.
//
// Песочница стоит первой: её вердикт DANGEROUS — это «в пакете нашли вредонос
// при запуске», то есть находка весомее и уязвимости по базе, и просроченной
// лицензии.
var BlockerPriority = []string{"sandbox_scan", "vuln_scan", "license", "quarantine"}

// BlockerStatus — статус пакета, пока шаг не погашен.
var BlockerStatus = map[string]string{
	"sandbox_scan": "awaiting_security",
	"vuln_scan":    "awaiting_security",
	"license":      "awaiting_legal",
	"quarantine":   "quarantined",
}

// OpenResults — какие результаты шага означают «решение роли ещё не принято».
// У проверки уязвимостей таких два: warn — база устарела, fail — балл выше
// порога. Оба уходят к DevSecOps, а не отклоняют пакет сами по себе.
var OpenResults = map[string][]string{
	"vuln_scan": {"warn", "fail"},
	// У песочницы их два по той же причине, что у проверки уязвимостей:
	// fail — вердикт DANGEROUS, warn — песочница не ответила или вернула
	// вердикт, которого мы не знаем. Оба случая — «публиковать нельзя, пока не
	// посмотрит человек», а не «чисто».
	//
	// Вердикта UNWANTED здесь нет СОЗНАТЕЛЬНО: он отдаётся результатом info —
	// пометка в карточке и в отчёте, публикацию не держит (решение
	// пользователя, docs/scanning-and-reports.md).
	"sandbox_scan": {"warn", "fail"},
	"license":      {"warn"},
	"quarantine":   {"warn"},
}

// BlockerRole — кто выносит решение. У карантина роли нет: это срок, а не
// решение (снять досрочно может DevSecOps, но обычный путь — истечение).
var BlockerRole = map[string]string{
	"sandbox_scan": "devsecops",
	"vuln_scan":    "devsecops",
	"license":      "legal",
	"quarantine":   "",
}

// BlockerWaitingFor — как назвать ожидание пользователю.
var BlockerWaitingFor = map[string]string{
	"sandbox_scan": "DevSecOps",
	"vuln_scan":    "DevSecOps",
	"license":      "юристов",
	"quarantine":   "окончания карантина",
}

// SecurityBlockers — шаги, которые снимает одно решение DevSecOps: он
// принимает решение по содержимому пакета целиком, а не по каждому сканеру
// отдельно.
//
// Снятых шагов тут нет по той же причине, что и в таблицах выше: снимать
// нечего. Строки banner_scan со старым результатом warn перевела в info
// миграция 0013.
var SecurityBlockers = []string{"vuln_scan", "sandbox_scan"}

// PendingBlockers — шаги, ждущие решения роли, в порядке убывания блокирующей
// силы.
func PendingBlockers(steps []domain.PipelineStep) []string {
	byCode := make(map[string]string, len(steps))
	for _, s := range steps {
		byCode[s.StepCode] = s.Result
	}
	var open []string
	for _, code := range BlockerPriority {
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

// IsBlockedBy — ждёт ли пакет решения по конкретному шагу.
func IsBlockedBy(steps []domain.PipelineStep, code string) bool {
	for _, s := range PendingBlockers(steps) {
		if s == code {
			return true
		}
	}
	return false
}

// StatusFromBlockers — статус пакета по самой блокирующей из непогашенных
// проверок; default, если непогашенных нет.
func StatusFromBlockers(steps []domain.PipelineStep, fallback string) string {
	if blockers := PendingBlockers(steps); len(blockers) > 0 {
		return BlockerStatus[blockers[0]]
	}
	return fallback
}

// IsOpenResult — считается ли такой результат шага непогашенной блокировкой.
func IsOpenResult(code, result string) bool {
	for _, open := range OpenResults[code] {
		if open == result {
			return true
		}
	}
	return false
}
