package pipeline

import (
	"errors"
	"testing"

	"moderation/internal/dragon"
)

func TestDragonManagers(t *testing.T) {
	if !dragonManagerSupported("go") {
		t.Error("Go должен поддерживаться")
	}
	for _, manager := range []string{"npm", "nuget", "pypi", "maven", "conan", "docker", "files", "git", "luarocks", "terraform", "php"} {
		if dragonManagerSupported(manager) {
			t.Errorf("manager %s не должен поддерживаться", manager)
		}
	}
}

func TestDragonInformationNeverBlocksPublication(t *testing.T) {
	outcome := dragonInformation("Dragon недоступен.", errors.New("timeout"), dragon.Result{
		RunID: "run-1", Status: "submitted",
	})
	if outcome.Result != "info" || outcome.Stop || outcome.Defer || outcome.ItemStatus != "" {
		t.Fatalf("информационный Dragon заблокировал публикацию: %+v", outcome)
	}
	if outcome.Details["run_id"] != "run-1" || outcome.Details["blocking"] != false {
		t.Fatalf("детали Dragon = %+v", outcome.Details)
	}
}

