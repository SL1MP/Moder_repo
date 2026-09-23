package api

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"context"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/maintenance"
	"moderation/internal/osv"
	"moderation/internal/policy"
	"moderation/internal/queue"
	"moderation/internal/repo"
)

// Административные маршруты.
//
// Перезагрузка политик закрывает долг, отмеченный в status.md: правка
// config/blacklist.yml требовала перезапуска api-go, а перезапуск рвёт
// открытые запросы — и происходит это ровно тогда, когда blacklist правят
// второпях, чтобы срочно запретить пакет.

// AdminHandler — зависимости административных маршрутов.
type AdminHandler struct {
	// Policies — держатель политик, общий с конвейером: перезагрузка обязана
	// менять то, по чему проверяются пакеты, а не отдельную копию для API.
	Policies *policy.Holder
	Repo     *repo.Repo
	Cfg      *config.Config
	// Index — снапшот базы уязвимостей: экран «Настройка» показывает его
	// версию и возраст. Это главная строка на экране — устаревший снапшот не
	// роняет сервис, он тихо переводит каждый пакет на ручное решение.
	Index osv.Index
	// Queue — очередь конвейера: по ней считаются залежавшиеся пакеты.
	Queue *queue.Queue
	// Sweep — ручной прогон сторожа очереди. nil — кнопка не подключается.
	Sweep func(ctx context.Context) (int, error)
	// OSVSync — ручной запуск синхронизации снапшота. nil — кнопка не
	// подключается: отдать её неработающей хуже, чем не отдать совсем.
	OSVSync func(ctx context.Context, force bool) (maintenance.SyncResult, error)
	Now     func() time.Time
}

func (h *AdminHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UTC()
}

// MountAdmin подключает административные маршруты.
//
// Роли разные и намеренно: читать настройки может любой вошедший — по ним
// видно, как устроен контур, и прятать это от DevSecOps незачем, — а менять
// что-либо может только admin. Снапшот уязвимостей — забота DevSecOps.
func MountAdmin(r chi.Router, h *AdminHandler, a *Auth) {
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		// Чтение: действующие настройки, состояние политик, кто разбирает
		// очередь. Экран «Настройка» существует ровно затем, чтобы «пакет
		// вечно проверяется» не приходилось диагностировать по логам
		// контейнеров.
		sub.Get("/api/v1/settings", h.Settings)
		sub.Get("/api/v1/settings/policies", h.PoliciesState)
		sub.Get("/api/v1/system/status", h.SystemStatus)
	})
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Use(RequireRoles("admin"))
		sub.Post("/api/v1/admin/reload", h.Reload)
		sub.Get("/api/v1/admin/audit", h.Audit)
		if h.Sweep != nil {
			sub.Post("/api/v1/admin/queue-sweep", h.QueueSweep)
		}
	})
	r.Group(func(sub chi.Router) {
		sub.Use(a.Authenticate)
		sub.Use(RequireRoles("devsecops"))
		sub.Get("/api/v1/admin/osv-versions", h.OSVVersions)
		if h.OSVSync != nil {
			sub.Post("/api/v1/admin/osv-sync", h.OSVSync_)
		}
	})
}

// Reload — POST /api/v1/admin/reload
//
// Перечитывает blacklist и справочник лицензий с диска.
//
// Код ответа различает исходы: 200 — оба файла прочитаны, 422 — хотя бы один
// сломан. Отдавать 200 на сломанный файл нельзя: администратор увидел бы
// «перезагружено» и ушёл, а работать продолжали бы прежние правила.
func (h *AdminHandler) Reload(w http.ResponseWriter, r *http.Request) {
	if h.Policies == nil {
		writeError(w, r, errInternal("Политики не подключены к сервису"))
		return
	}

	result := h.Policies.Reload()

	// Перезагрузка меняет правила проверки для всех пакетов сразу — в журнале
	// аудита обязан остаться след, кто и когда это сделал.
	if user, ok := CurrentUser(r.Context()); ok && user != nil && h.Repo != nil {
		entry := domain.AuditLog{
			ActorID: &user.ID, ActorName: user.Username,
			Action: "policies_reloaded", EntityType: "policy",
			Source: "ui", IP: ClientIP(r), CreatedAt: h.now(),
			NewValue: map[string]any{
				"blacklist_rules":  result.BlacklistRules,
				"licenses_allowed": result.LicensesAllow,
				"blacklist_error":  result.BlacklistError,
				"licenses_error":   result.LicensesError,
				"ok":               result.OK(),
			},
		}
		if role := auth.PrimaryRole(user.Roles); role != "" {
			entry.ActorRole = &role
		}
		if rid := RequestID(r.Context()); rid != "" {
			entry.RequestID = &rid
		}
		if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
			// Не повод отвечать ошибкой: политики уже перечитаны, и сообщить
			// об этом важнее, чем о ненаписанной строке журнала.
			defaultLogger.Printf("[%s] аудит перезагрузки политик не записан: %v",
				RequestID(r.Context()), err)
		}
	}

	status := http.StatusOK
	if !result.OK() {
		// Прежние правила при этом остались действовать — сломанный файл их
		// не подменяет (см. policy.Holder.Reload). Сказать об этом надо
		// прямо, иначе «не перезагрузилось» читается как «правил больше нет».
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]any{
		"ok":     result.OK(),
		"result": result,
		"note": "Сломанный файл не подменяет прежние правила: если перезагрузка не удалась, " +
			"продолжают действовать те, что были загружены раньше.",
	})
}

// Settings — GET /api/v1/settings
//
// Действующие значения ВМЕСТЕ С ИМЕНЕМ ПЕРЕМЕННОЙ. Администратор смотрит сюда,
// чтобы понять, почему сервис ведёт себя не так, как он ожидал: ответ
// «QUARANTINE_DAYS = 14» закрывает вопрос за секунду, а «карантин: 14 дней»
// оставляет искать, где это правится.
func (h *AdminHandler) Settings(w http.ResponseWriter, r *http.Request) {
	if h.Cfg == nil {
		writeError(w, r, errInternal("Конфигурация не подключена к сервису"))
		return
	}
	writeJSON(w, http.StatusOK, h.Cfg.Catalog())
}

// PoliciesState — GET /api/v1/settings/policies
//
// Состояние blacklist, справочника лицензий и снапшота уязвимостей. Всё, чем
// сервис выносит вердикт и что при этом лежит не в базе, а в файлах.
func (h *AdminHandler) PoliciesState(w http.ResponseWriter, r *http.Request) {
	if h.Policies == nil {
		writeError(w, r, errInternal("Политики не подключены к сервису"))
		return
	}
	blacklist, licenses := h.Policies.Blacklist(), h.Policies.Licenses()

	payload := map[string]any{
		"blacklist": map[string]any{
			"path": blacklist.Path, "rules": blacklist.Rules,
			"loaded_at": blacklist.LoadedAt, "error": blacklist.Err,
		},
		"licenses": map[string]any{
			"path":      licenses.Path,
			"allowed":   licenses.SortedAllowed(),
			"forbidden": licenses.SortedForbidden(),
			"loaded_at": licenses.LoadedAt, "error": licenses.Err,
		},
		"reloaded_at": h.Policies.ReloadedAt(),
	}
	payload["vuln_index"] = h.vulnIndexState(r)
	writeJSON(w, http.StatusOK, payload)
}

// vulnIndexState — состояние снапшота уязвимостей.
//
// Главная строка экрана: устаревший снапшот не роняет сервис, он тихо
// переводит каждый пакет на ручное решение DevSecOps, и снаружи это выглядит
// как «модерация стала медленной», а не как поломка.
func (h *AdminHandler) vulnIndexState(r *http.Request) map[string]any {
	maxStaleness := 3
	if h.Cfg != nil {
		maxStaleness = h.Cfg.OSVMaxStalenessDays
	}
	// stale=true по умолчанию: «не знаем, свежий ли снапшот» и «снапшот
	// свежий» — разные вещи, и вторым первое подменять нельзя. Экран
	// показывает булево значение, и false в нём читается как «всё хорошо».
	state := map[string]any{"max_staleness_days": maxStaleness, "stale": true}
	if h.Index == nil {
		state["error"] = "индекс уязвимостей не подключён"
		return state
	}
	state["source"] = h.Index.Source()

	version, err := h.Index.CurrentVersion(r.Context())
	if err != nil {
		state["error"] = err.Error()
		return state
	}
	if version == nil {
		// Отличать «снапшот ни разу не загружали» от «загружен и устарел»
		// обязательно: чинить эти случаи надо по-разному.
		state["version"] = nil
		state["note"] = "Снапшот ни разу не загружался — проверка уязвимостей " +
			"отправляет каждый пакет к DevSecOps."
		return state
	}
	state["version"] = version.Version
	state["published_at"] = version.PublishedAt
	state["record_count"] = version.RecordCount
	// Возраст неизвестен — stale остаётся true (см. выше): дата публикации
	// снапшота не обязательна, а решать по ней, можно ли одобрять
	// автоматически, — обязательно.
	if age := version.AgeDays(h.now()); age != nil {
		state["age_days"] = math.Round(*age*100) / 100
		state["stale"] = *age > float64(maxStaleness)
	}
	return state
}

// SystemStatus — GET /api/v1/system/status
//
// Кто разбирает очередь и не завис ли в ней кто-нибудь. Экран «Настройка»
// показывает это, чтобы «пакет вечно проверяется» не приходилось
// диагностировать по логам контейнеров.
func (h *AdminHandler) SystemStatus(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{}
	if h.Cfg != nil {
		payload["watchdog"] = map[string]any{
			"enabled":             h.Cfg.PipelineWatchdogEnabled,
			"interval_seconds":    int(h.Cfg.PipelineWatchdogInterval.Seconds()),
			"stuck_after_seconds": int(h.Cfg.PipelineStuckAfter.Seconds()),
		}
	}

	queueState := map[string]any{}
	if h.Queue != nil {
		if queued, running, err := h.Queue.Depth(r.Context()); err == nil {
			queueState["queued"], queueState["running"] = queued, running
		} else {
			queueState["error"] = err.Error()
		}
	}
	if h.Repo != nil && h.Cfg != nil {
		stuck, err := h.Repo.StuckItemIDs(r.Context(), h.Cfg.PipelineStuckAfter, 50)
		switch {
		case err != nil:
			queueState["stuck_error"] = err.Error()
		default:
			queueState["stuck_items"] = len(stuck)
			queueState["stuck_item_ids"] = stuck
			// Определение то же, что у метрики worker_alive: если в очереди
			// лежат пакеты, которых никто не забрал дольше порога, значит
			// очередь не разбирается — что бы ни показывал `docker compose ps`.
			payload["worker"] = map[string]any{
				"queue_is_moving": len(stuck) == 0,
				"note": "Признак косвенный: он отвечает на вопрос «разбирается ли " +
					"очередь», а не «жив ли процесс воркера».",
			}
		}
	}
	payload["queue"] = queueState
	writeJSON(w, http.StatusOK, payload)
}

// Audit — GET /api/v1/admin/audit
func (h *AdminHandler) Audit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := repo.AuditFilter{
		EntityType: query.Get("entity_type"),
		EntityID:   query.Get("entity_id"),
		Action:     query.Get("action"),
		Actor:      query.Get("actor"),
		Limit:      intOrDefault(query.Get("limit"), 100),
		Offset:     intOrDefault(query.Get("offset"), 0),
	}
	entries, err := h.Repo.ListAuditLog(r.Context(), filter)
	if err != nil {
		writeError(w, r, errInternal("Журнал аудита не прочитан").Because(err))
		return
	}

	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		out = append(out, map[string]any{
			"id": entry.ID, "actor_name": entry.ActorName, "actor_role": entry.ActorRole,
			"action": entry.Action, "entity_type": entry.EntityType, "entity_id": entry.EntityID,
			"old_value": entry.OldValue, "new_value": entry.NewValue,
			"source": entry.Source, "source_title": auditSourceTitle(entry.Source),
			"comment": entry.Comment, "ip": entry.IP, "created_at": entry.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// auditSourceTitle — откуда пришло действие, по-человечески.
// Порт SOURCE_TITLES из app/services/audit.py.
func auditSourceTitle(source string) string {
	switch source {
	case "ui":
		return "UI"
	case "api":
		return "REST API"
	case "task":
		return "фоновая задача"
	case "cli":
		return "CLI"
	}
	return source
}

// OSVVersions — GET /api/v1/admin/osv-versions
func (h *AdminHandler) OSVVersions(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Repo.ListVulnIndexVersions(r.Context(), 50)
	if err != nil {
		writeError(w, r, errInternal("Версии снапшота не прочитаны").Because(err))
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, v := range rows {
		out = append(out, map[string]any{
			"id": v.ID, "version": v.Version, "source": v.Source, "checksum": v.Checksum,
			"published_at": v.PublishedAt, "downloaded_at": v.DownloadedAt,
			"record_count": v.RecordCount, "is_active": v.IsActive,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// OSVSync_ — POST /api/v1/admin/osv-sync
//
// Синхронизация выполняется ЗДЕСЬ И СЕЙЧАС, а не ставится в очередь: у
// go-версии нет брокера, а «поставлено в очередь» без очереди — это ответ,
// после которого ничего не происходит. Запрос долгий (снапшот — сотни
// мегабайт), и это честнее молчаливого бездействия.
//
// Подчёркивание в имени — потому что поле структуры уже занято под функцию,
// которая делает работу. Метод и поле не могут называться одинаково.
func (h *AdminHandler) OSVSync_(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "true"

	user, _ := CurrentUser(r.Context())
	if user != nil && h.Repo != nil {
		entry := domain.AuditLog{
			ActorID: &user.ID, ActorName: user.Username,
			Action: "osv_sync_triggered", EntityType: "vuln_index_version",
			Source: "ui", IP: ClientIP(r), CreatedAt: h.now(),
			NewValue: map[string]any{"force": force},
		}
		if role := auth.PrimaryRole(user.Roles); role != "" {
			entry.ActorRole = &role
		}
		if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
			defaultLogger.Printf("[%s] аудит запуска синхронизации не записан: %v",
				RequestID(r.Context()), err)
		}
	}

	result, err := h.OSVSync(r.Context(), force)
	if err != nil {
		writeError(w, r, errUpstream("Снапшот не загружен").Because(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"updated": result.Updated, "version": result.Version, "records": result.Records,
	})
}

// QueueSweep — POST /api/v1/admin/queue-sweep
//
// Ручной прогон сторожа очереди: то же, что он делает по расписанию, но
// сейчас. Нужен, когда воркер только что подняли и ждать следующего тика
// незачем.
func (h *AdminHandler) QueueSweep(w http.ResponseWriter, r *http.Request) {
	processed, err := h.Sweep(r.Context())
	if err != nil {
		writeError(w, r, errInternal("Прогон очереди не выполнен").Because(err))
		return
	}

	if user, ok := CurrentUser(r.Context()); ok && user != nil && h.Repo != nil {
		entry := domain.AuditLog{
			ActorID: &user.ID, ActorName: user.Username,
			Action: "queue_swept", EntityType: "system",
			Source: "api", IP: ClientIP(r), CreatedAt: h.now(),
			NewValue: map[string]any{"processed": processed},
		}
		if role := auth.PrimaryRole(user.Roles); role != "" {
			entry.ActorRole = &role
		}
		if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
			defaultLogger.Printf("[%s] аудит прогона очереди не записан: %v",
				RequestID(r.Context()), err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"processed": processed})
}

// intOrDefault — целое из строки запроса, без ошибки.
//
// Отдельно от intParam: тот возвращает ошибку, и маршруты списков отвечают по
// ней 422 — неверный limit в них меняет выдачу. Здесь же это фильтр журнала:
// мусор в limit не повод не показать журнал, и падать на нём незачем.
func intOrDefault(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 {
		return fallback
	}
	return value
}
