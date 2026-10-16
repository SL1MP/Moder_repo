package pipeline

import (
	"errors"
	"testing"

	"moderation/internal/dragon"
)

func TestDragonManagers(t *testing.T) {
	for _, manager := range []string{"go", "npm", "nuget", "pypi", "maven", "conan", "files", "luarocks", "terraform", "php"} {
		if !dragonManagerSupported(manager) {
			t.Errorf("manager %s должен поддерживаться", manager)
		}
	}
	for _, manager := range []string{"docker", "git", "unknown"} {
		if dragonManagerSupported(manager) {
			t.Errorf("manager %s не должен поддерживаться", manager)
		}
	}
}

func TestDragonRepositoryPerManagerNeverFallsBackToGo(t *testing.T) {
	cfg := Config{DragonRepositoryID: "legacy-go", DragonRepositoryIDs: map[string]string{
		"npm": "npm-id", "pypi": "pypi-id",
	}}
	for manager, want := range map[string]string{
		"npm": "npm-id", "pypi": "pypi-id", "go": "legacy-go",
		"maven": "", "docker": "", "git": "",
	} {
		if got := dragonRepositoryFor(cfg, manager); got != want {
			t.Errorf("manager %s: ID %q, ожидалось %q", manager, got, want)
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

