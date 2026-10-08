package pipeline

import (
	"testing"

	"moderation/internal/dragon"
)

func TestDragonBlockingFindings(t *testing.T) {
	summary := dragon.Summary{Critical: 1, High: 2, Medium: 3, Low: 4, Unknown: 5}
	cases := map[string]int{
		"critical": 6,
		"high":     8,
		"medium":   11,
		"low":      15,
	}
	for threshold, want := range cases {
		if got := dragonBlockingFindings(summary, threshold); got != want {
			t.Errorf("threshold %s: got %d, want %d", threshold, got, want)
		}
	}
}

func TestStagingArtifactURLPreservesPathAndEscapesSegments(t *testing.T) {
	got := stagingArtifactURL(
		"http://nexus:8081/repository/moderation-staging/",
		"docker/library/postgres/14.23@sha256:abc/image oci.tar.gz",
	)
	want := "http://nexus:8081/repository/moderation-staging/docker/library/postgres/14.23@sha256:abc/image%20oci.tar.gz"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestDragonManagers(t *testing.T) {
	for _, manager := range []string{"npm", "nuget", "pypi", "maven", "go", "conan", "docker"} {
		if !dragonManagerSupported(manager) {
			t.Errorf("manager %s должен поддерживаться", manager)
		}
	}
	for _, manager := range []string{"files", "git", "luarocks", "terraform", "php"} {
		if dragonManagerSupported(manager) {
			t.Errorf("manager %s не должен поддерживаться", manager)
		}
	}
}

