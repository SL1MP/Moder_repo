package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkerMetricsHandler(t *testing.T) {
	handler := workerMetricsHandler()
	for _, tc := range []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{path: "/health", wantStatus: http.StatusOK, wantBody: "ok\n"},
		{path: "/metrics", wantStatus: http.StatusOK, wantBody: "go_gc_duration_seconds"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://worker"+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d, ожидался %d", response.Code, tc.wantStatus)
			}
			if !strings.Contains(response.Body.String(), tc.wantBody) {
				t.Fatalf("ответ %q не содержит %q", response.Body.String(), tc.wantBody)
			}
		})
	}
}
