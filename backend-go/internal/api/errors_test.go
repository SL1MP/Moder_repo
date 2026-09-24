package api

import (
	"net/http/httptest"
	"testing"
)

func TestWriteJSONDisablesCaching(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, 200, map[string]string{"status": "running"})
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, ожидалось no-store", got)
	}
}
