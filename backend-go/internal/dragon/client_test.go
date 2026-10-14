package dragon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientUploadsArchiveAndPollsReturnedStatusURL(t *testing.T) {
	payload := []byte("test archive")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	var polls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/api/runs/archive":
			if got := r.Header.Get("Accept"); got != "*/*" {
				t.Errorf("Accept = %q", got)
			}
			if r.ContentLength <= 0 || len(r.TransferEncoding) != 0 {
				t.Errorf("multipart должен иметь Content-Length: length=%d transfer=%v",
					r.ContentLength, r.TransferEncoding)
			}
			if got := r.URL.Query().Get("pipeline_id"); got != "packages" {
				t.Errorf("pipeline_id = %q", got)
			}
			if got := r.URL.Query().Get("repository_id"); got != "example-repository-id" {
				t.Errorf("repository_id = %q", got)
			}
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatal(err)
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			buf, err := io.ReadAll(file)
			if err != nil {
				t.Fatal(err)
			}
			if string(buf) != string(payload) || header.Filename != "module.zip" {
				t.Errorf("file=%q filename=%q", buf, header.Filename)
			}
			if got := header.Header.Get("Content-Type"); got != "application/x-zip-compressed" {
				t.Errorf("file content type = %q", got)
			}
			if r.FormValue("name") != "github.com/acme/module" ||
				r.FormValue("label") != "v1.5.7" || r.FormValue("publish") != "true" ||
				r.FormValue("priority") != "4" {
				t.Errorf("form name=%q label=%q publish=%q priority=%q",
					r.FormValue("name"), r.FormValue("label"),
					r.FormValue("publish"), r.FormValue("priority"))
			}
			if r.FormValue("variables") != `{"SEC_AIE_PROJECT_LANGUAGE_GROUPS":"none"}` {
				t.Errorf("variables = %s", r.FormValue("variables"))
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "run-1", "status_url": "/api/runs/run-1/status",
				"run_url": "/runs/run-1", "sha256": digest,
				"format": "zip", "files": 2, "bytes": len(payload), "skipped": 0,
			})
		case "/api/runs/run-1/status":
			done := polls.Add(1) > 1
			status := map[bool]string{true: "success", false: "running"}[done]
			jobs := []map[string]any{}
			if done {
				jobs = []map[string]any{
					{"name": "gitleaks", "scanner": "gitleaks", "status": "success",
						"log": []map[string]string{{"c": "plain", "t": "leaks found: 2"}}},
					{"name": "semgrep", "scanner": "semgrep", "status": "success",
						"log": []map[string]string{{"c": "plain", "t": "Findings: 58 (58 blocking)"}, {"c": "plain", "t": "Ran 890 rules: 58 findings."}}},
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "run-1", "status": status, "pipeline": "default-security",
				"repo": "go", "repository_id": "example-repository-id", "archive": "module.zip",
				"jobs": jobs, "oakshield_url": "https://oakshield.example/engagement/1",
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
		PipelineID: "packages", RepositoryID: "example-repository-id", ExternalID: "moderation:item:42",
		Publish: true, Priority: 4,
		Artifact: Artifact{
			Manager: "go", Name: "github.com/acme/module", Version: "v1.5.7", Filename: "module.zip",
			SHA256: digest, Payload: payload,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.ArtifactVerified || !result.Done || !result.Success || polls.Load() != 2 {
		t.Fatalf("result = %+v, polls = %d", result, polls.Load())
	}
	if result.Findings.Secrets != 2 || result.Findings.CodeFindings != 58 || result.Findings.Total != 60 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	if result.ArchiveSHA256 != digest || result.ArchiveFiles != 2 || result.StatusURL == "" {
		t.Fatalf("archive metadata = %+v", result)
	}
	if result.RepositoryID != "example-repository-id" || result.OakshieldURL == "" || len(result.Jobs) != 2 {
		t.Fatalf("status metadata = %+v", result)
	}
}

func TestClientTreatsDragonSuccessAsTerminalInformation(t *testing.T) {
	payload := []byte("archive")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/runs/archive" {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"id": "run-1", "status_url": "/status/run-1", "sha256": digest,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "run-1", "status": "success"})
	}))
	defer server.Close()
	result, err := New(Config{BaseURL: server.URL, HTTPClient: server.Client(), Timeout: time.Second}).Scan(
		context.Background(), Request{PipelineID: "p", Artifact: Artifact{Filename: "a.zip", SHA256: digest, Payload: payload}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Done || !result.Success || result.Findings.Total != 0 {
		t.Fatalf("plain success must be terminal information: %+v", result)
	}
}

func TestClientRejectsChangedArchiveDigest(t *testing.T) {
	payload := []byte("archive")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id": "run-1", "status_url": "/status/run-1", "sha256": strings.Repeat("0", 64),
		})
	}))
	defer server.Close()
	_, err := New(Config{BaseURL: server.URL, HTTPClient: server.Client()}).Scan(
		context.Background(), Request{PipelineID: "p", Artifact: Artifact{Filename: "a.zip", SHA256: digest, Payload: payload}},
	)
	if err == nil || !strings.Contains(err.Error(), "принял другие байты") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientRequiresArchiveIntegrityReference(t *testing.T) {
	client := New(Config{BaseURL: "http://dragon.test"})
	_, err := client.Scan(context.Background(), Request{PipelineID: "packages"})
	if err == nil {
		t.Fatal("ожидалась ошибка для артефакта без байтов и SHA-256")
	}
}
