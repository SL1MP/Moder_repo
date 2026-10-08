package dragon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientCreatesAndPollsArtifactRun(t *testing.T) {
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/artifact-runs":
			var got Request
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.Artifact.SHA256 != "abc" || got.ExternalID != "moderation:item:42" {
				t.Errorf("request = %+v", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "run-1"})
		case "/api/runs/run-1/status":
			done := polls.Add(1) > 1
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "run-1", "status": "success", "done": done,
				"success": done, "artifact_verified": done, "evidence_complete": done,
				"summary": map[string]int{"high": 1},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(Config{
		BaseURL: server.URL, Token: "secret", PollInterval: time.Millisecond,
		Timeout: time.Second, HTTPClient: server.Client(),
	})
	result, err := client.Scan(context.Background(), Request{
		PipelineID: "packages", ExternalID: "moderation:item:42",
		Artifact: Artifact{URL: "http://nexus/a.whl", SHA256: "abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.ArtifactVerified || !result.EvidenceComplete || result.Summary.High != 1 || polls.Load() != 2 {
		t.Fatalf("result = %+v, polls = %d", result, polls.Load())
	}
}

func TestClientRequiresIntegrityReference(t *testing.T) {
	client := New(Config{BaseURL: "http://dragon.test"})
	_, err := client.Scan(context.Background(), Request{PipelineID: "packages"})
	if err == nil {
		t.Fatal("ожидалась ошибка для артефакта без URL/SHA-256")
	}
}

