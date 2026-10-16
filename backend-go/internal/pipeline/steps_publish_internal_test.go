package pipeline

import (
	"testing"

	"moderation/internal/artifactstore"
)

func TestPublishedArtifactURLSeparatesDockerBrowseAndPullEndpoints(t *testing.T) {
	digest := "sha256:acafcd1b28e40db49774008d08b50e40bfda39ffd9b0741bdc9257948664a644"
	cfg := Config{ArtifactDockerBrowseURL: "https://repo.example/artifactory/docker-moderated"}
	target := artifactstore.Target{
		Manager: "docker",
		Name:    "3proxy/3proxy",
		Version: "0.9.4@" + digest,
	}
	got := publishedArtifactURL(cfg, target, "https://docker.example/3proxy/3proxy:0.9.4@"+digest)
	want := "https://repo.example/artifactory/docker-moderated/3proxy/3proxy/0.9.4/"
	if got != want {
		t.Fatalf("browse URL = %q, ожидалось %q", got, want)
	}
}

func TestPublishedArtifactURLKeepsFallbackForOtherManagers(t *testing.T) {
	fallback := "https://repo.example/artifactory/maven-moderated/example/tool/1.0/tool-1.0.jar"
	got := publishedArtifactURL(Config{ArtifactDockerBrowseURL: "https://repo.example/docker"}, artifactstore.Target{
		Manager: "maven", Name: "example:tool", Version: "1.0",
	}, fallback)
	if got != fallback {
		t.Fatalf("Maven URL = %q, ожидалось %q", got, fallback)
	}
}
