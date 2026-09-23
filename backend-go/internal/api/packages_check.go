package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"io"

	"moderation/internal/domain"
	"moderation/internal/registry"
)

// maxCheckBodyBytes — предел тела запроса проверки. Список записей, а не файл:
// мегабайта хватает на тысячи строк, а безразмерное тело — это способ занять
// память сервиса одним запросом.
const maxCheckBodyBytes = 1 << 20

// POST /api/v1/packages/check — «Найти пакет».
//
// Порт backend/app/api/v1/packages.py::check_packages. Отвечает не
// «найдено/не найдено», а состоянием по существу: можно ставить, идёт проверка
// или проверку не прошёл.
//
// Различие принципиальное. Строка в базе появляется в момент заведения заявки,
// то есть ДО всех проверок, и «пакет есть в базе» само по себе не означает
// ничего. Разработчик, прочитавший «есть», поставил бы непроверенный пакет.

// checkRequest — тело запроса. Записи принимаются и строками
// («requests==2.31.0»), и парой полей: первое приходит из поля ввода, второе —
// из формы с раздельными полями имени и версии.
type checkRequest struct {
	Manager  string            `json:"manager"`
	Packages []json.RawMessage `json:"packages"`
}

// checkEntry — запись в виде пары полей.
type checkEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Check — POST /api/v1/packages/check
func (h *PackagesHandler) Check(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCheckBodyBytes))
	if err != nil {
		writeError(w, r, errValidation("Тело запроса не прочитано").Because(err))
		return
	}
	var body checkRequest
	if err := json.Unmarshal(raw, &body); err != nil {
		writeError(w, r, errValidation(
			"Ожидается JSON с полями manager и packages").Because(err))
		return
	}
	if len(body.Packages) == 0 {
		writeError(w, r, errValidation("Список packages пуст"))
		return
	}
	plugin, pluginErr := h.Registry.Get(body.Manager)
	if pluginErr != nil {
		writeError(w, r, errValidation(pluginErr.Error()))
		return
	}
	// Предел тот же, что у заведения заявки: проверка ходит в базу по каждой
	// записи, и безразмерный список превращает один запрос в тысячу.
	if limit := h.Cfg.MaxPackagesPerRequest; limit > 0 && len(body.Packages) > limit {
		writeError(w, r, errValidation(fmt.Sprintf(
			"За один раз можно проверить не больше %d пакетов, прислано %d",
			limit, len(body.Packages))))
		return
	}

	results := make([]map[string]any, 0, len(body.Packages))
	for _, raw := range body.Packages {
		label, ref, parseErr := parseCheckEntry(plugin, raw)
		if parseErr != nil {
			results = append(results, map[string]any{
				"raw": label, "state": "invalid_format",
				"message":         parseErr.Error(),
				"expected_format": plugin.EntryFormat(),
			})
			continue
		}
		results = append(results, h.checkOne(r.Context(), plugin, label, ref))
	}
	// Ключ «packages», а не «results»: его читает интерфейс, и переименование
	// при переносе означало бы пустой список на странице «Найти пакет».
	writeJSON(w, http.StatusOK, map[string]any{
		"manager": plugin.Code(), "packages": results,
	})
}

// parseCheckEntry разбирает одну запись в любом из двух видов.
func parseCheckEntry(plugin registry.Plugin, raw json.RawMessage) (string, registry.Ref, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		label := strings.TrimSpace(text)
		ref, err := registry.ParseEntry(plugin, label)
		return label, ref, err
	}

	var entry checkEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return strings.TrimSpace(string(raw)), registry.Ref{},
			fmt.Errorf("запись не разобрана: ожидается строка «%s» либо объект с полями name и version",
				plugin.EntryFormat())
	}
	label := strings.TrimSpace(entry.Name + " " + entry.Version)
	ref, err := registry.MakeRef(plugin, entry.Name, entry.Version)
	return label, ref, err
}

// checkOne — состояние одной версии.
func (h *PackagesHandler) checkOne(
	ctx context.Context, plugin registry.Plugin, label string, ref registry.Ref,
) map[string]any {
	found, err := h.Repo.FindVersion(ctx, ref.Manager, ref.Name, ref.Version)
	if err != nil {
		// Ошибка чтения базы по ОДНОЙ записи не должна валить весь ответ:
		// остальные записи проверены, и терять их результат незачем. Но и
		// выдавать её за «не найдено» нельзя — это разные вещи.
		return map[string]any{
			"raw": label, "name": ref.DisplayName, "version": ref.RawVersion,
			"state":   "error",
			"message": "Не удалось проверить по базе: " + err.Error(),
		}
	}
	if found == nil {
		return map[string]any{
			"raw": label, "name": ref.DisplayName, "version": ref.RawVersion,
			"state":   "not_found",
			"message": "В базе нет — нужно заводить заявку.",
		}
	}

	payload := map[string]any{
		"raw": label, "name": ref.DisplayName, "version": ref.RawVersion,
		"package_version_id": found.ID,
		"status":             found.Status,
		"status_title":       domain.StatusTitles[found.Status],
		"link":               fmt.Sprintf("/api/v1/packages/%d", found.ID),
		"status_reason":      found.StatusReason,
	}

	switch {
	case found.Status == "approved":
		payload["state"] = "approved"
		payload["message"] = "Одобрен — можно ставить из внутреннего репозитория."
		payload["install_command"] = plugin.InstallCommand(
			ref, h.Cfg.ArtifactBaseURL, h.Cfg.ArtifactRepo(ref.Manager))

	case domain.Contains(domain.PendingVersionStatuses, found.Status):
		// Заявка уже есть — подсказываем её номер, чтобы не заводили вторую.
		payload["state"] = "in_progress"
		where := ""
		if item := h.latestItem(ctx, found.ID); item != nil {
			payload["request_id"] = item.RequestID
			payload["current_step"] = item.CurrentStep
			payload["next_action"] = item.NextAction
			where = fmt.Sprintf(" (заявка #%d)", item.RequestID)
		}
		payload["message"] = fmt.Sprintf(
			"Ставить нельзя: пакет ещё не прошёл модерацию — %s%s. "+
				"Повторную заявку заводить не нужно.",
			strings.ToLower(domain.StatusTitles[found.Status]), where)

	default:
		payload["state"] = "blocked"
		payload["message"] = blockedMessage(
			domain.StatusTitles[found.Status], deref(found.StatusReason))
	}
	return payload
}

// latestItem — последняя заявка по версии. nil, если её нет или не прочиталась:
// номер заявки — подсказка, а не условие ответа, и терять из-за неё весь
// результат проверки незачем.
func (h *PackagesHandler) latestItem(ctx context.Context, versionID int64) *domain.RequestItem {
	items, err := h.Repo.ListItemsByPackageVersion(ctx, versionID)
	if err != nil || len(items) == 0 {
		return nil
	}
	latest := items[0]
	for i := range items {
		if items[i].ID > latest.ID {
			latest = items[i]
		}
	}
	return &latest
}

// blockedMessage собирает объяснение для пакета, не прошедшего проверку.
//
// Причина приходит из разных мест (вердикт сканера, комментарий роли, правило
// blacklist), и точку в конце никто не гарантирует — дописываем, иначе два
// предложения склеиваются в одно нечитаемое.
func blockedMessage(statusTitle, reason string) string {
	parts := []string{fmt.Sprintf("Ставить нельзя: %s.", strings.ToLower(statusTitle))}
	if reason = strings.TrimSpace(reason); reason != "" {
		if !strings.ContainsRune(".!?", rune(reason[len(reason)-1])) {
			reason += "."
		}
		parts = append(parts, reason)
	}
	parts = append(parts, "Подберите другую версию или замену.")
	return strings.Join(parts, " ")
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
