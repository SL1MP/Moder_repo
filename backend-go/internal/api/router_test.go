package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Все маршруты должны собираться в один роутер: chi падает паникой на попытке
// смонтировать два обработчика на один путь, и увидеть это в бою — худший
// вариант, потому что падает весь сервис на старте.
func TestFullRouterMounts(t *testing.T) {
	store := newMemStore()
	h := newHarness(t, store, nil)
	router := NewRouter(nil, Options{
		Auth:     &AuthHandler{Auth: h.auth, Cfg: h.cfg},
		Reports:  &ReportsHandler{},
		Packages: &PackagesHandler{Cfg: h.cfg},
		Requests: &RequestsHandler{Cfg: h.cfg},
	})
	for _, path := range []string{
		"/api/v1/auth/config", "/api/v1/auth/me",
		"/api/v1/managers", "/api/v1/managers/detect?filename=go.sum",
		"/api/v1/packages", "/api/v1/packages/1",
		"/api/v1/requests", "/api/v1/requests/1",
		"/api/v1/request-items/1/reports",
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s: маршрут не смонтирован", path)
		}
	}
}

// Список заявок должен отвечать и без завершающего слэша: именно так его
// запрашивает фронтенд (`/requests`), а chi.Route регистрирует индекс как «/».
func TestCollectionPathsWithoutTrailingSlash(t *testing.T) {
	h := newHarness(t, newMemStore(), nil)
	router := NewRouter(nil, Options{
		Auth:     &AuthHandler{Auth: h.auth, Cfg: h.cfg},
		Requests: &RequestsHandler{Cfg: h.cfg},
	})
	for _, path := range []string{"/api/v1/requests", "/api/v1/requests/"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s: 404 — маршрут не найден", path)
		}
		if rec.Code == http.StatusMovedPermanently {
			t.Errorf("%s: редирект вместо ответа (%s)", path, rec.Header().Get("Location"))
		}
	}
}
