package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSwappableHandlerChangesNewRequests(t *testing.T) {
	handler := newSwappableHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("old"))
	}))

	request := func() string {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return rec.Body.String()
	}
	if got := request(); got != "old" {
		t.Fatalf("до замены получено %q", got)
	}

	handler.Swap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("new"))
	}))
	if got := request(); got != "new" {
		t.Fatalf("после замены получено %q", got)
	}
}

func TestSwappableHandlerLetsInflightRequestFinish(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	handler := newSwappableHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("old"))
	}))

	oldResponse := make(chan string, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		oldResponse <- rec.Body.String()
	}()
	<-started

	handler.Swap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("new"))
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Body.String(); got != "new" {
		t.Fatalf("новый запрос попал в старый handler: %q", got)
	}

	close(release)
	if got := <-oldResponse; got != "old" {
		t.Fatalf("активный запрос не закончил работу на старом handler: %q", got)
	}
}
