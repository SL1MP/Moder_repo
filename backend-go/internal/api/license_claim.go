package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"moderation/internal/auth"
	"moderation/internal/decisions"
	"moderation/internal/domain"
	"moderation/internal/licensesnap"
	"moderation/internal/policy"
)

// POST /api/v1/items/{itemID}/license-claim — заявление лицензии разработчиком.
//
// Порт backend/app/api/v1/decisions.py::claim_license. Нужен там, где
// справочник лицензию не разрешил, а она на деле допустима: разработчик
// прикладывает ссылку на текст, юрист смотрит и решает.
//
// Ссылка не просто сохраняется: по ней снимается текст. Ссылка через год
// может вести в никуда, а решение юриста принято по конкретному тексту, и
// предъявить надо именно его.

// snapshotLimit — сколько символов текста лицензии сохраняем.
//
// 200 000 — с запасом на самые многословные лицензии (GPL-3.0 около 35 000).
// Предел нужен потому, что по ссылке может оказаться что угодно, вплоть до
// дампа, и класть его целиком в базу незачем.
const snapshotLimit = 200_000

// claimBody — тело запроса.
type claimBody struct {
	URL string `json:"url"`
	// SPDXID необязателен: разработчик может не знать идентификатора и просто
	// приложить ссылку.
	SPDXID  string `json:"spdx_id"`
	Comment string `json:"comment"`
}

// ClaimLicense — POST /api/v1/items/{itemID}/license-claim
func (h *DecisionsHandler) ClaimLicense(w http.ResponseWriter, r *http.Request) {
	item, user, ok := h.itemAndUser(w, r)
	if !ok {
		return
	}

	// Заявить лицензию может автор заявки — это его пакет — либо роль,
	// которая и так видит все заявки.
	if !user.HasRole("admin", "devsecops", "legal") {
		request, err := h.Repo.GetModerationRequest(r.Context(), item.RequestID)
		if err != nil {
			writeError(w, r, errInternal("Заявка не прочитана").Because(err))
			return
		}
		if request == nil || request.AuthorID != user.ID {
			writeError(w, r, errForbidden(
				"Заявить лицензию может автор заявки, юрист, DevSecOps или администратор"))
			return
		}
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxDecisionBodyBytes))
	if err != nil {
		writeError(w, r, errValidation("Тело запроса не прочитано").Because(err))
		return
	}
	var body claimBody
	if err := json.Unmarshal(raw, &body); err != nil {
		writeError(w, r, errValidation("Ожидается JSON с полем url").Because(err))
		return
	}

	url := strings.TrimSpace(body.URL)
	if !strings.HasPrefix(strings.ToLower(url), "http://") &&
		!strings.HasPrefix(strings.ToLower(url), "https://") {
		writeError(w, r, errValidation(
			"Ссылка на лицензию должна начинаться с http:// или https://"))
		return
	}

	snapshot, snapErr := h.fetchSnapshot(r.Context(), url)
	if snapErr != nil {
		writeError(w, r, snapErr)
		return
	}

	result, err := h.Decisions.ClaimLicense(r.Context(), decisions.ClaimInput{
		Item: item, URL: url, SPDXID: body.SPDXID, Comment: body.Comment,
		Snapshot: snapshot, ActorID: user.ID, ActorName: user.DisplayName(), Source: "ui",
	}, licenseCatalog{policies: h.Policies})
	if err != nil {
		h.writeDecisionError(w, r, err)
		return
	}
	if result.NotifyError != nil {
		defaultLogger.Printf("[%s] уведомление юристам о заявленной лицензии не создано: %v",
			RequestID(r.Context()), result.NotifyError)
	}

	h.auditClaim(r, user, result)

	// Свёртка статуса заявки пересчитывается: пакет сменил состояние, и
	// оставить заявку прежней значило бы показать людям неправду.
	if errs := h.Decisions.Deliver(r.Context(), item.ID, nil); len(errs) > 0 {
		for _, err := range errs {
			defaultLogger.Printf("[%s] после заявления лицензии: %v", RequestID(r.Context()), err)
		}
	}

	writeJSON(w, http.StatusCreated, h.claimView(r, *result.Claim))
}

// fetchSnapshot снимает текст лицензии по ссылке.
//
// Заодно это проверка доступности: ссылка, требующая авторизации, юристу
// бесполезна — он её не откроет. Поэтому недоступность здесь ошибка ввода, а
// не «сохраним как есть, разберутся».
func (h *DecisionsHandler) fetchSnapshot(ctx context.Context, url string) (string, *Error) {
	client := h.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	// Сначала пробуем сырой адрес: ссылку берут из адресной строки браузера, а
	// это страница просмотра, отдающая HTML-документ целиком.
	target := licensesnap.RawURL(url)
	resp, err := fetchOnce(ctx, client, target)
	if err == nil && resp.StatusCode >= 400 && target != url {
		// Догадка про «сырой» адрес не сработала — пробуем исходную ссылку.
		resp.Body.Close()
		resp, err = fetchOnce(ctx, client, url)
	}
	if err != nil {
		return "", errValidation(
			"Ссылка недоступна с сервера модерации: " + err.Error()).Because(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", errValidation(fmt.Sprintf(
			"Ссылка недоступна без авторизации (ответ %d). Приложите публично доступный URL.",
			resp.StatusCode))
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, snapshotLimit*4))
	if err != nil {
		return "", errValidation("Не удалось прочитать ответ по ссылке").Because(err)
	}

	text := licensesnap.Clean(string(payload), resp.Header.Get("Content-Type"), snapshotLimit)
	if strings.TrimSpace(text) == "" {
		return "", errValidation(
			"По ссылке пустой ответ — приложите страницу с текстом лицензии")
	}
	return text, nil
}

func fetchOnce(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain, text/html;q=0.9, */*;q=0.5")
	return client.Do(req)
}

// licenseCatalog — справочник SPDX для проверки заявленного идентификатора.
//
// Через держатель, а не по загруженной копии: POST /admin/reload перечитывает
// файл без перезапуска, и проверка по копии отвергала бы лицензию, которую в
// справочник только что добавили.
type licenseCatalog struct{ policies *policy.Holder }

func (c licenseCatalog) Knows(spdxID string) bool {
	if c.policies == nil {
		return true // справочника нет — проверять нечем, отвергать нечестно
	}
	_, ok := c.policies.Licenses().Entry(spdxID)
	return ok
}

func (c licenseCatalog) KnownIDs(limit int) []string {
	if c.policies == nil {
		return nil
	}
	return c.policies.Licenses().KnownIDs(limit)
}

// auditClaim пишет заявление в журнал.
func (h *DecisionsHandler) auditClaim(r *http.Request, user *domain.User, result *decisions.ClaimResult) {
	entityID := strconv.FormatInt(result.Claim.Claim.ID, 10)
	entry := domain.AuditLog{
		ActorID: &user.ID, ActorName: user.Username,
		Action: "license_claimed", EntityType: "license_claim", EntityID: &entityID,
		Source: "ui", IP: ClientIP(r), CreatedAt: h.now(),
		NewValue: map[string]any{
			"url":                result.Claim.Claim.URL,
			"spdx_id":            result.Claim.Claim.SPDXID,
			"package_version_id": result.Claim.Claim.PackageVersionID,
		},
	}
	if role := auth.PrimaryRole(user.Roles); role != "" {
		entry.ActorRole = &role
	}
	if rid := RequestID(r.Context()); rid != "" {
		entry.RequestID = &rid
	}
	if err := h.Repo.InsertAuditLog(r.Context(), entry); err != nil {
		defaultLogger.Printf("[%s] аудит заявления лицензии не записан: %v",
			RequestID(r.Context()), err)
	}
}
