package vumana

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUploadMatchesSBOMUtilsContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/sbom/upload" {
			t.Errorf("запрос = %s %s", r.Method, r.URL.Path)
			return
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			t.Error(err)
			return
		}
		defer file.Close()
		body, _ := io.ReadAll(file)
		if header.Filename != "pkg.cdx.json" || !json.Valid(body) {
			t.Errorf("multipart file = %q, %s", header.Filename, body)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"bom-1","url":"/sbom/bom-1"}`))
	}))
	defer server.Close()

	client := New(Config{APIURL: server.URL + "/api/", PublicURL: "https://vumana.example/", Token: "secret", HTTPClient: server.Client()})
	result, err := client.Upload(context.Background(), "pkg.cdx.json", []byte(`{"bomFormat":"CycloneDX"}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != "bom-1" || result.BrowserURL != "https://vumana.example/#/sbom/bom-1" {
		t.Fatalf("result = %+v", result)
	}
}
