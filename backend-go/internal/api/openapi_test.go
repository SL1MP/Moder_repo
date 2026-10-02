package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"moderation/internal/api"
)

func TestOpenAPIRoutesArePublicAndUsable(t *testing.T) {
	server := httptest.NewServer(api.NewRouter(nil))
	defer server.Close()

	for _, path := range []string{"/api/docs", "/api/redoc"} {
		resp, err := http.Get(server.URL + path) //nolint:gosec // локальный httptest
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", path, resp.StatusCode, body)
		}
		if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") ||
			!strings.Contains(string(body), "/api/openapi.json") {
			t.Errorf("%s не содержит UI OpenAPI: headers=%v body=%s", path, resp.Header, body)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("%s отдан без Content-Security-Policy", path)
		}
	}
}

func TestOpenAPISpecDocumentsGoAPI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	rec := httptest.NewRecorder()
	api.NewRouter(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var spec struct {
		OpenAPI    string                    `json:"openapi"`
		Paths      map[string]map[string]any `json:"paths"`
		Components map[string]any            `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatalf("спецификация не JSON: %v", err)
	}
	if spec.OpenAPI != "3.0.3" {
		t.Errorf("openapi=%q", spec.OpenAPI)
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/auth/token"},
		{http.MethodPost, "/api/v1/requests"},
		{http.MethodPost, "/api/v1/items/{itemID}/security-decision"},
		{http.MethodGet, "/api/v1/request-items/{itemID}/reports/{file}"},
		{http.MethodGet, "/api/v1/request-items/{itemID}/sboms/{file}"},
		{http.MethodPost, "/api/v1/admin/osv-sync"},
	} {
		methods := spec.Paths[route.path]
		if methods == nil || methods[strings.ToLower(route.method)] == nil {
			t.Errorf("в OpenAPI отсутствует %s %s", route.method, route.path)
		}
	}
	if len(spec.Paths) < 40 {
		t.Errorf("описано только %d путей — спецификация неполна", len(spec.Paths))
	}
	if spec.Components["securitySchemes"] == nil {
		t.Error("в OpenAPI отсутствует bearer security scheme")
	}

	download, ok := spec.Paths["/api/v1/request-items/{itemID}/reports/{file}"]["get"].(map[string]any)
	if !ok {
		t.Fatal("операция скачивания отчёта имеет неожиданный формат")
	}
	parameters, ok := download["parameters"].([]any)
	if !ok || len(parameters) != 2 {
		t.Fatalf("path-параметры скачивания отчёта: %#v", download["parameters"])
	}
	fileParameter, ok := parameters[1].(map[string]any)
	if !ok {
		t.Fatalf("параметр file имеет неожиданный формат: %#v", parameters[1])
	}
	fileSchema, _ := fileParameter["schema"].(map[string]any)
	if fileParameter["name"] != "file" || fileSchema["type"] != "string" {
		t.Errorf("file должен быть строковым path-параметром: %#v", fileParameter)
	}
}
