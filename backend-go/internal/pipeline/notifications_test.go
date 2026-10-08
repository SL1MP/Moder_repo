package pipeline

import "testing"

func TestNotificationsForOutcomeKeepRoleAndEventTogether(t *testing.T) {
	items := notificationsForOutcome(StepOutcome{
		NotifyEvent: EventAwaitsSecurity,
		NotifyRoles: []string{"devsecops", "legal"},
		Message:     "ожидаются два решения",
	}, 42)
	if len(items) != 2 {
		t.Fatalf("уведомлений %d, ожидалось 2", len(items))
	}
	byRole := map[string]Notification{}
	for _, item := range items {
		if len(item.Roles) != 1 {
			t.Fatalf("роли не разделены: %+v", item)
		}
		byRole[item.Roles[0]] = item
	}
	if byRole["devsecops"].Event != EventAwaitsSecurity {
		t.Errorf("DevSecOps получил событие %q", byRole["devsecops"].Event)
	}
	if byRole["legal"].Event != EventAwaitsLegal {
		t.Errorf("юрист получил событие %q", byRole["legal"].Event)
	}
}
