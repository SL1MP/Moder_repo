package api

import (
	"testing"

	"moderation/internal/config"
	"moderation/internal/domain"
	"moderation/internal/registry"
	"moderation/internal/repo"
)

func TestArtifactViewsUsesDockerBrowseURL(t *testing.T) {
	digest := "sha256:acafcd1b28e40db49774008d08b50e40bfda39ffd9b0741bdc9257948664a644"
	wrongRegistryURL := "https://docker.example/3proxy/3proxy:0.9.4@" + digest
	h := &PackagesHandler{
		Cfg: &config.Config{
			ArtifactDockerBrowseURL: "https://repo.example/artifactory/docker-moderated",
		},
		Registry: registry.New(registry.Config{}),
	}
	row := &repo.VersionRow{
		Manager: "docker",
		Name:    "3proxy/3proxy",
		Version: domain.PackageVersion{
			Version:    "0.9.4@" + digest,
			RawVersion: "0.9.4@" + digest,
		},
	}
	views := h.artifactViews(row, []domain.Artifact{{
		Filename: "image.oci.tar.gz",
		NexusURL: &wrongRegistryURL,
		Status:   "published",
	}})
	if len(views) != 1 {
		t.Fatalf("артефактов = %d, ожидался 1", len(views))
	}
	got, ok := views[0]["nexus_url"].(*string)
	if !ok || got == nil {
		t.Fatalf("nexus_url имеет неожиданный тип: %#v", views[0]["nexus_url"])
	}
	want := "https://repo.example/artifactory/docker-moderated/3proxy/3proxy/0.9.4/"
	if *got != want {
		t.Fatalf("ссылка кнопки = %q, ожидалось %q", *got, want)
	}
}
