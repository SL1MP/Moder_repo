package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"moderation/internal/domain"
	"moderation/internal/repo"
	"moderation/internal/storage"
)

// Отчёты о сканировании: список по пакету заявки и выдача файла.
//
// Файлы лежат в объектном хранилище, а не в БД, и отдаются потоком через
// сервис, а не прямой ссылкой на хранилище: хранилище внутреннее и наружу не
// публикуется, а доступ к отчёту обязан проходить те же проверки прав, что и
// сама заявка (авторизация — фаза 4, здесь оставлен явный шов).

// ReportsHandler — зависимости обработчиков отчётов.
type ReportsHandler struct {
	Repo    *repo.Repo
	Storage storage.Store
}

// reportView — элемент списка отчётов.
type reportView struct {
	StepCode         string    `json:"step_code"`
	StepTitle        string    `json:"step_title"`
	Scanner          string    `json:"scanner"`
	Rules            string    `json:"rules,omitempty"`
	State            string    `json:"state"`
	StateTitle       string    `json:"state_title"`
	Threshold        string    `json:"threshold"`
	FindingsTotal    int       `json:"findings_total"`
	FindingsBlocking int       `json:"findings_blocking"`
	WorstSeverity    string    `json:"worst_severity,omitempty"`
	Detail           string    `json:"detail,omitempty"`
	DurationMs       int       `json:"duration_ms,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	// Ссылки на файлы — относительные пути этого же API, а не ключи в
	// хранилище: ключ наружу отдавать незачем, а ссылка сразу пригодна для UI.
	JSONURL string `json:"json_url"`
	HTMLURL string `json:"html_url"`
}

// stateTitles — состояние прогона по-русски. unavailable читается как «не
// выполнена», а НЕ как «чисто»: это разные вещи, и интерфейс обязан их
// различать.
var stateTitles = map[string]string{
	"clean":       "Срабатываний нет",
	"findings":    "Есть срабатывания",
	"unavailable": "Проверка не выполнена",
}

func toReportView(r domain.ScanReport) reportView {
	view := reportView{
		StepCode: r.StepCode, StepTitle: domain.StepTitles[r.StepCode],
		Scanner: r.Scanner, State: r.State, StateTitle: stateTitles[r.State],
		Threshold: r.Threshold, FindingsTotal: r.FindingsTotal,
		FindingsBlocking: r.FindingsBlocking, CreatedAt: r.CreatedAt,
		JSONURL: fmt.Sprintf("/api/v1/request-items/%d/reports/%s.json", r.RequestItemID, r.StepCode),
		HTMLURL: fmt.Sprintf("/api/v1/request-items/%d/reports/%s.html", r.RequestItemID, r.StepCode),
	}
	if r.Rules != nil {
		view.Rules = *r.Rules
	}
	if r.WorstSeverity != nil {
		view.WorstSeverity = *r.WorstSeverity
	}
	if r.Detail != nil {
		view.Detail = *r.Detail
	}
	if r.DurationMs != nil {
		view.DurationMs = *r.DurationMs
	}
	return view
}

// List — GET /api/v1/request-items/{itemID}/reports
func (h *ReportsHandler) List(w http.ResponseWriter, r *http.Request) {
	itemID, ok := pathInt64(w, r, "itemID")
	if !ok {
		return
	}
	rows, err := h.Repo.ListScanReports(r.Context(), itemID)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить список отчётов").Because(err))
		return
	}
	views := make([]reportView, 0, len(rows))
	for _, row := range rows {
		views = append(views, toReportView(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request_item_id": itemID,
		"reports":         views,
	})
}

// Download — GET /api/v1/request-items/{itemID}/reports/{file}
// где file — `banner_scan.json`, `sast_scan.html` и т.п.
func (h *ReportsHandler) Download(w http.ResponseWriter, r *http.Request) {
	itemID, ok := pathInt64(w, r, "itemID")
	if !ok {
		return
	}
	stepCode, format, ok := splitReportFile(chi.URLParam(r, "file"))
	if !ok {
		writeError(w, r, errNotFound(
			"Отчёт запрашивается как banner_scan.json, banner_scan.html, sast_scan.json или sast_scan.html"))
		return
	}

	report, err := h.Repo.GetScanReport(r.Context(), itemID, stepCode)
	if err != nil {
		writeError(w, r, errInternal("Не удалось получить отчёт").Because(err))
		return
	}
	if report == nil {
		// Отличать «прогона не было» от «файл потерялся» важно: первое —
		// нормальное состояние (шаг выключен или ещё не дошли), второе —
		// авария хранилища.
		writeError(w, r, errNotFound("Отчёт по этому шагу отсутствует: прогон сканера не выполнялся"))
		return
	}

	key := report.JSONKey
	if format == "html" {
		key = report.HTMLKey
	}
	body, err := h.Storage.Get(r.Context(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, r, errNotFound(
				"Файл отчёта не найден в хранилище — возможно, он был вычищен").Because(err))
			return
		}
		writeError(w, r, errUpstream("Хранилище отчётов недоступно").Because(err))
		return
	}

	w.Header().Set("Content-Type", storage.ContentTypeFor(format))
	// inline, а не attachment: HTML-отчёт должен открываться в браузере, а не
	// скачиваться файлом. Имя всё равно задаём — оно пригодится при сохранении.
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`inline; filename="%s-%d.%s"`, stepCode, itemID, format))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// splitReportFile разбирает `sast_scan.json` на код шага и формат. Проверка по
// белым спискам, а не по разбору строки: код шага и формат уходят в ключ
// объекта, и принимать сюда произвольную строку из URL нельзя.
func splitReportFile(file string) (stepCode, format string, ok bool) {
	for _, code := range domain.ScanReportStepCodes {
		for _, ext := range []string{"json", "html"} {
			if file == code+"."+ext {
				return code, ext, true
			}
		}
	}
	return "", "", false
}

func pathInt64(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	raw := chi.URLParam(r, name)
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		// Декодируем для сообщения: chi отдаёт сегмент пути как есть, и
		// кириллица в нём выглядит как %d0%b0%d0%b1%d0%b2 — сообщение об
		// ошибке становится нечитаемым ровно там, где должно помогать.
		shown := raw
		if decoded, err := url.PathUnescape(raw); err == nil {
			shown = decoded
		}
		writeError(w, r, errBadRequest(fmt.Sprintf("Некорректный идентификатор в пути: %q", shown)))
		return 0, false
	}
	return value, true
}
