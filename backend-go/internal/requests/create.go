package requests

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"moderation/internal/domain"
	"moderation/internal/queue"
	"moderation/internal/resolve"
)

// ErrConflict — заявка с таким Idempotency-Key уже есть.
var ErrConflict = errors.New("заявка уже создана")

// ConflictError несёт номер уже созданной заявки: клиенту нужен именно он, а
// не просто «конфликт».
type ConflictError struct{ RequestID int64 }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("заявка с таким Idempotency-Key уже создана (#%d)", e.RequestID)
}

func (e *ConflictError) Is(target error) bool { return target == ErrConflict }

// CreateInput — что нужно для создания заявки помимо разобранного списка.
type CreateInput struct {
	Author            *domain.User
	AuthorRole        string
	Reason            string
	Source            string // api | ui | cli | gitlab
	IdempotencyKey    string
	OriginFile        string
	IncludeTransitive bool
	// Resolve — итог раскрытия зависимостей, если оно было. Хранится на
	// заявке: по нему в карточке видно, полное ли дерево.
	Resolve *resolve.Result
}

// Create заводит заявку и ставит её пакеты в очередь.
//
// Постановка в очередь идёт ПОСЛЕ фиксации заявки: воркер забирает пакет по
// строке в базе, и разбудить его раньше, чем строка видна, значит разбудить
// впустую. Обратный порядок в python-версии (задача в Redis до коммита)
// приводил к тому, что воркер получал задачу на ещё не существующий пакет.
func (s *Service) Create(ctx context.Context, result ParseResult, in CreateInput, q *queue.Queue) (*domain.ModerationRequest, []int64, error) {
	if in.IdempotencyKey != "" {
		existing, err := s.Repo.GetModerationRequestByIdempotencyKey(ctx, in.IdempotencyKey)
		if err != nil {
			return nil, nil, err
		}
		if existing != nil {
			return nil, nil, &ConflictError{RequestID: existing.ID}
		}
	}

	request := domain.ModerationRequest{
		AuthorID: in.Author.ID, Manager: result.Manager, Status: "pending",
		Source: valueOr(in.Source, "api"), IncludeTransitive: in.IncludeTransitive,
		Warnings: result.Warnings,
	}
	if in.Resolve != nil {
		depth := in.Resolve.MaxDepth
		summary := in.Resolve.Summary()
		request.ResolveDepth, request.ResolveSummary = &depth, &summary
	}
	if in.AuthorRole != "" {
		request.AuthorRole = &in.AuthorRole
	}
	if in.Reason != "" {
		request.Reason = &in.Reason
	}
	if in.IdempotencyKey != "" {
		request.IdempotencyKey = &in.IdempotencyKey
	}
	if in.OriginFile != "" {
		request.OriginFile = &in.OriginFile
	}

	created, err := s.Repo.CreateModerationRequest(ctx, request)
	if err != nil {
		return nil, nil, err
	}

	// Пакеты заводятся по возрастанию глубины: строка родителя обязана
	// существовать раньше, чем на неё сошлётся потомок.
	pending := result.New()
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].Depth < pending[j].Depth })

	var itemIDs []int64
	itemByKey := make(map[string]int64, len(pending))
	for _, parsed := range pending {
		ref := parsed.Ref
		pkg, err := s.Repo.GetOrCreatePackage(ctx, ref.Manager, ref.Name, ref.DisplayName)
		if err != nil {
			return nil, nil, err
		}
		version, err := s.Repo.CreatePackageVersion(ctx, pkg.ID, ref.Version, ref.RawVersion)
		if err != nil {
			return nil, nil, err
		}
		newItem := domain.RequestItem{
			RequestID: created.ID, PackageVersionID: version.ID,
			RequestedName: ref.DisplayName, RequestedVersion: ref.RawVersion,
			DependencyKind: valueOr(parsed.DependencyKind, "direct"),
			Depth:          parsed.Depth,
			Status:         "queued",
		}
		if parentID, ok := itemByKey[parsed.ParentKey]; ok && parsed.ParentKey != "" {
			newItem.ParentItemID = &parentID
		}
		if parsed.RequiredRange != "" {
			required := parsed.RequiredRange
			newItem.RequiredRange = &required
		}
		item, err := s.Repo.CreateRequestItem(ctx, newItem)
		if err != nil {
			return nil, nil, err
		}
		if parsed.Key != "" {
			itemByKey[parsed.Key] = item.ID
		}
		itemIDs = append(itemIDs, item.ID)
	}

	s.audit(ctx, created, result, in)

	// Будим воркеров один раз на заявку, а не на каждый пакет: они всё равно
	// разберут очередь до конца, а двести уведомлений подряд — это двести
	// лишних пробуждений.
	if q != nil && len(itemIDs) > 0 {
		if err := q.Notify(ctx); err != nil {
			// Не повод отменять заявку: пакеты уже в очереди, и воркер
			// подберёт их следующим опросом.
			return created, itemIDs, nil
		}
	}
	return created, itemIDs, nil
}

func (s *Service) audit(ctx context.Context, request *domain.ModerationRequest, result ParseResult, in CreateInput) {
	entityID := fmt.Sprintf("%d", request.ID)
	newValue := map[string]any{
		"manager":         request.Manager,
		"packages":        rawList(result.Packages, StateNew),
		"already_in_base": rawList(result.Packages, StateAlreadyInBase),
		"invalid":         rawList(result.Packages, StateInvalidFormat),
		"source":          request.Source,
	}
	if in.Reason != "" {
		newValue["reason"] = in.Reason
	}
	entry := domain.AuditLog{
		ActorID: &in.Author.ID, ActorName: in.Author.Username,
		Action: "request_created", EntityType: "moderation_request", EntityID: &entityID,
		NewValue: newValue, Source: auditSource(request.Source), CreatedAt: time.Now().UTC(),
	}
	if in.AuthorRole != "" {
		entry.ActorRole = &in.AuthorRole
	}
	if err := s.Repo.InsertAuditLog(ctx, entry); err != nil {
		// Заявка уже создана; неполный журнал хуже полного, но отменять из-за
		// него работу пользователя нельзя.
		s.logAuditFailure(err)
	}
}

// logAuditFailure сообщает о неудачной записи аудита. Заявка к этому моменту
// уже создана: неполный журнал хуже полного, но отменять из-за него работу
// пользователя нельзя.
func (s *Service) logAuditFailure(err error) {
	if s.OnAuditError != nil {
		s.OnAuditError(err)
	}
}

func auditSource(source string) string {
	switch source {
	case "api", "ui", "cli":
		return source
	}
	return "api"
}

func rawList(packages []Parsed, state string) []string {
	out := []string{}
	for _, p := range packages {
		if p.State == state {
			out = append(out, p.Raw)
		}
	}
	return out
}
