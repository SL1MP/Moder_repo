package maintenance

import (
	"context"
	"fmt"

	"moderation/internal/decisions"
	"moderation/internal/osv"
)

// Перепроверка одобренных пакетов после обновления базы уязвимостей.
//
// Смысл задачи в том, что решение о пакете принимается по данным, которые
// устаревают. Пакет, одобренный вчера, сегодня может оказаться уязвимым — и
// узнать об этом должен сервис, а не разработчик из новостей.
//
// Отзыв идёт ТОЛЬКО по новой уязвимости. Если находка выше порога уже была
// известна на момент одобрения, значит её видел DevSecOps и принял решение;
// отзывать по ней при каждом обновлении базы — значит молча отменять чужое
// решение, и сервис станет невозможно использовать.

// RescanResult — итог перепроверки.
type RescanResult struct {
	Checked int
	Revoked int
}

// RescanApproved перепроверяет одобренные пакеты по текущей базе уязвимостей.
//
// Ошибка по одному пакету не прекращает обход: тысяча одобренных пакетов не
// должна зависеть от одной битой записи в снапшоте.
func (s *Service) RescanApproved(ctx context.Context, index osv.Index, maxScore float64, indexVersionID *int64) (RescanResult, error) {
	var out RescanResult
	if index == nil {
		return out, fmt.Errorf("индекс уязвимостей не настроен")
	}
	ids, err := s.Repo.ApprovedVersionIDs(ctx)
	if err != nil {
		return out, err
	}

	for _, id := range ids {
		row, err := s.Repo.GetVersionRow(ctx, id)
		if err != nil || row == nil || row.Version.Status != "approved" {
			continue
		}
		// Что по этой версии уже было известно на момент одобрения.
		known := map[string]bool{}
		previous, err := s.Repo.ListVulnerabilities(ctx, id)
		if err != nil {
			s.logger().Warn("перепроверка пропущена", "version", id, "error", err)
			continue
		}
		for _, v := range previous {
			known[v.ExternalID] = true
		}

		findings, err := index.Query(ctx, row.Manager, row.Name, row.Version.Version)
		if err != nil {
			s.logger().Warn("перепроверка не выполнена", "version", id, "error", err)
			continue
		}
		out.Checked++

		worst := 0.0
		var fresh []osv.Finding
		for _, f := range findings {
			score := f.Score()
			if score > worst {
				worst = score
			}
			if score > maxScore && !known[f.ExternalID] {
				fresh = append(fresh, f)
			}
		}
		if err := s.Repo.SetVersionVulnSummary(ctx, id, worst, indexVersionID); err != nil {
			s.logger().Warn("итог перепроверки не сохранён", "version", id, "error", err)
		}
		if len(fresh) == 0 {
			continue
		}

		top := fresh[0]
		for _, f := range fresh[1:] {
			if f.Score() > top.Score() {
				top = f
			}
		}
		reason := fmt.Sprintf(
			"Новая уязвимость %s (балл %.1f выше порога %.1f) обнаружена после обновления базы OSV.",
			top.ExternalID, top.Score(), maxScore)

		version := row.Version
		result, err := s.Decisions.RevokeVersion(ctx, decisions.RevokeInput{
			Version: &version, Manager: row.Manager, Name: row.Name,
			DisplayName: row.DisplayName, Reason: reason, Source: "task",
			Unpublish: true,
		}, s.Artifacts)
		if err != nil {
			s.logger().Error("пакет не отозван", "version", id, "error", err)
			continue
		}
		if result.UnpublishError != nil {
			// Статус уже изменён, но копия могла остаться в артефактори —
			// молчать об этом нельзя: из неё продолжат ставить.
			s.logger().Error("пакет отозван, но с публикации не снят",
				"version", id, "error", result.UnpublishError)
		}
		for _, deliverErr := range s.Decisions.Deliver(ctx, itemOrZero(result.Items), &decisions.Result{
			Siblings: result.Items, Notifications: result.Notifications,
		}) {
			s.logger().Warn("последствия отзыва", "version", id, "error", deliverErr)
		}
		out.Revoked++
		s.logger().Warn("пакет отозван по новой уязвимости",
			"пакет", row.DisplayName, "версия", version.RawVersion, "уязвимость", top.ExternalID)
	}

	if out.Checked > 0 {
		s.logger().Info("перепроверка одобренных завершена",
			"проверено", out.Checked, "отозвано", out.Revoked)
	}
	return out, nil
}

func itemOrZero(items []int64) int64 {
	if len(items) == 0 {
		return 0
	}
	return items[0]
}
