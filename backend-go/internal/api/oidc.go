package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"moderation/internal/auth"
	"moderation/internal/config"
	"moderation/internal/repo"
)

const oidcStateCookie = "moderation_oidc_state"

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type oidcState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Redirect string `json:"redirect"`
	Expires  int64  `json:"expires"`
}

// RuntimeOIDCVerifier проверяет токены по OIDC-настройке, которая меняется в
// web без restart. Сам Verifier (и его JWKS-кэш) пересобирается только при
// смене issuer; обычный запрос не загружает discovery/JWKS заново.
type RuntimeOIDCVerifier struct {
	store *repo.Repo
	cfg   *config.Config
	mu    sync.Mutex
	key   string
	value *auth.Verifier
}

func NewRuntimeOIDCVerifier(store *repo.Repo, cfg *config.Config) *RuntimeOIDCVerifier {
	if store == nil || cfg == nil {
		return nil
	}
	return &RuntimeOIDCVerifier{store: store, cfg: cfg}
}

func (v *RuntimeOIDCVerifier) Decode(ctx context.Context, token string) (auth.Claims, error) {
	settings, err := v.store.OIDCSettings(ctx)
	if err != nil {
		return auth.Claims{}, err
	}
	if !settings.Enabled || settings.Issuer == "" {
		return auth.Claims{}, fmt.Errorf("OIDC disabled")
	}
	jwksIssuer := oidcJWKSIssuer(v.cfg, settings.Issuer)
	key := settings.Issuer + "\x00" + jwksIssuer
	v.mu.Lock()
	if v.value == nil || v.key != key {
		v.value = auth.NewVerifier(auth.Settings{
			Issuer: jwksIssuer, AcceptedIssuers: []string{settings.Issuer}, Mapper: v.cfg,
			LocalAuthSecret: v.cfg.LocalAuthSecret, LocalTokenTTL: v.cfg.LocalAuthTokenTTL,
		}, nil, nil)
		v.key = key
	}
	verifier := v.value
	v.mu.Unlock()
	return verifier.Decode(ctx, token)
}

func (h *AuthHandler) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	settings, err := h.oidcSettings(r.Context())
	if err != nil || !settings.Enabled || settings.Issuer == "" || settings.ClientID == "" {
		http.Redirect(w, r, "/?sso_error="+url.QueryEscape("OIDC не настроен"), http.StatusFound)
		return
	}
	discovery, _, err := h.discoverOIDC(r.Context(), settings.Issuer)
	if err != nil {
		http.Redirect(w, r, "/?sso_error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	state, err := randomURLToken()
	if err != nil {
		writeError(w, r, errInternal("OIDC state не создан").Because(err))
		return
	}
	nonce, err := randomURLToken()
	if err != nil {
		writeError(w, r, errInternal("OIDC nonce не создан").Because(err))
		return
	}
	verifier, err := randomURLToken()
	if err != nil {
		writeError(w, r, errInternal("OIDC PKCE не создан").Because(err))
		return
	}
	redirect := oidcRedirectURI(settings, r)
	value, err := h.signOIDCState(oidcState{State: state, Nonce: nonce, Verifier: verifier, Redirect: redirect, Expires: h.Auth.now().Add(10 * time.Minute).Unix()})
	if err != nil {
		writeError(w, r, errInternal("OIDC state не подписан").Because(err))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: value, Path: "/api/v1/auth/oidc", MaxAge: 600,
		HttpOnly: true, Secure: strings.HasPrefix(redirect, "https://"), SameSite: http.SameSiteLaxMode})
	challengeRaw := sha256.Sum256([]byte(verifier))
	params := url.Values{"client_id": {settings.ClientID}, "response_type": {"code"},
		"scope": {"openid profile email"}, "redirect_uri": {redirect}, "state": {state}, "nonce": {nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challengeRaw[:])}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, discovery.AuthorizationEndpoint+"?"+params.Encode(), http.StatusFound)
}

func (h *AuthHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	settings, err := h.oidcSettings(r.Context())
	base := oidcAppBase(settings, r)
	fail := func(message string) {
		http.Redirect(w, r, base+"/?sso_error="+url.QueryEscape(message), http.StatusFound)
	}
	cookie, cookieErr := r.Cookie(oidcStateCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Path: "/api/v1/auth/oidc", MaxAge: -1, HttpOnly: true})
	if err != nil {
		fail("OIDC настройки не прочитаны")
		return
	}
	if value := r.URL.Query().Get("error"); value != "" {
		fail("Keycloak: " + value)
		return
	}
	if cookieErr != nil || r.URL.Query().Get("code") == "" || r.URL.Query().Get("state") == "" {
		fail("Нет code/state/cookie; возможно, cookie истекла")
		return
	}
	state, err := h.parseOIDCState(cookie.Value)
	if err != nil || state.State != r.URL.Query().Get("state") || state.Expires < h.Auth.now().Unix() {
		fail("OIDC state не прошёл проверку")
		return
	}
	discovery, jwksIssuer, err := h.discoverOIDC(r.Context(), settings.Issuer)
	if err != nil {
		fail(err.Error())
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {settings.ClientID},
		"code": {r.URL.Query().Get("code")}, "redirect_uri": {state.Redirect}, "code_verifier": {state.Verifier}}
	if settings.ClientSecret != "" {
		form.Set("client_secret", settings.ClientSecret)
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fail("Обмен OIDC code не выполнен: " + err.Error())
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fail(fmt.Sprintf("Обмен OIDC code отклонён (%d)", resp.StatusCode))
		return
	}
	var tokenResponse struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &tokenResponse); err != nil || tokenResponse.IDToken == "" {
		fail("Keycloak не вернул id_token")
		return
	}
	var claims auth.Claims
	if h.Auth.RuntimeOIDC != nil {
		claims, err = h.Auth.RuntimeOIDC.Decode(r.Context(), tokenResponse.IDToken)
	} else {
		verifier := auth.NewVerifier(auth.Settings{Issuer: jwksIssuer, AcceptedIssuers: []string{settings.Issuer}, Mapper: h.Cfg,
			LocalAuthSecret: h.Cfg.LocalAuthSecret, LocalTokenTTL: h.Cfg.LocalAuthTokenTTL}, nil, nil)
		claims, err = verifier.Decode(r.Context(), tokenResponse.IDToken)
	}
	if err != nil {
		fail("id_token не прошёл проверку: " + err.Error())
		return
	}
	if claims.Raw["nonce"] != state.Nonce || !audienceContains(claims.Raw["aud"], settings.ClientID) {
		fail("id_token nonce/audience не совпали")
		return
	}
	if claims.Username == "" {
		claims.Username = claims.Subject
	}
	user, err := h.Auth.Repo.SyncUser(r.Context(), repo.UserClaims{Subject: claims.Subject, Username: claims.Username,
		Email: claims.Email, FullName: claims.FullName}, h.Auth.now())
	if err != nil || user == nil || !user.IsActive {
		fail("OIDC-пользователь не создан или отключён")
		return
	}
	access, refresh, ttl, err := h.issuePair(r, user)
	if err != nil {
		fail("Локальная сессия не создана")
		return
	}
	fragment := url.Values{"access_token": {access}, "refresh_token": {refresh}, "expires_in": {fmt.Sprint(ttl)}}
	http.Redirect(w, r, base+"/oidc/callback#"+fragment.Encode(), http.StatusFound)
}

func (h *AuthHandler) oidcSettings(ctx context.Context) (repo.OIDCSettings, error) {
	if h.Auth.SessionRepo == nil {
		return repo.OIDCSettings{}, fmt.Errorf("OIDC store is not configured")
	}
	return h.Auth.SessionRepo.OIDCSettings(ctx)
}

func discoverOIDC(ctx context.Context, issuer string) (oidcDiscovery, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return oidcDiscovery{}, fmt.Errorf("OIDC discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcDiscovery{}, fmt.Errorf("OIDC discovery вернул %d", resp.StatusCode)
	}
	var value oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&value); err != nil {
		return value, err
	}
	if value.AuthorizationEndpoint == "" || value.TokenEndpoint == "" {
		return value, fmt.Errorf("в OIDC discovery нет authorization_endpoint/token_endpoint")
	}
	return value, nil
}

// discoverOIDC сохраняет совместимость старой compose-конфигурации, в которой
// OIDC_ISSUER доступен контейнеру, а OIDC_PUBLIC_ISSUER — браузеру. OakShield-
// настройка из web обычно содержит один canonical issuer; внутренний адрес
// применяется только когда runtime issuer в точности совпал с унаследованным
// BrowserIssuer из env. Так смена issuer в UI не продолжает ходить в старый
// realm незаметно.
func (h *AuthHandler) discoverOIDC(ctx context.Context, issuer string) (oidcDiscovery, string, error) {
	fetchIssuer := oidcJWKSIssuer(h.Cfg, issuer)
	useSplitIssuer := fetchIssuer != issuer
	if useSplitIssuer {
		fetchIssuer = strings.TrimRight(fetchIssuer, "/")
	}
	value, err := discoverOIDC(ctx, fetchIssuer)
	if err != nil {
		return value, fetchIssuer, err
	}
	if useSplitIssuer {
		value.AuthorizationEndpoint = replaceIssuerPrefix(value.AuthorizationEndpoint, fetchIssuer, issuer)
	}
	return value, fetchIssuer, nil
}

func oidcJWKSIssuer(cfg *config.Config, issuer string) string {
	issuer = strings.TrimRight(issuer, "/")
	legacyPublic := strings.TrimRight(cfg.BrowserIssuer(), "/")
	legacyInternal := strings.TrimRight(cfg.OIDCIssuer, "/")
	if issuer == legacyPublic && legacyInternal != "" && legacyInternal != legacyPublic {
		return legacyInternal
	}
	return issuer
}

func replaceIssuerPrefix(endpoint, from, to string) string {
	from = strings.TrimRight(from, "/")
	to = strings.TrimRight(to, "/")
	if endpoint == from {
		return to
	}
	if strings.HasPrefix(endpoint, from+"/") {
		return to + strings.TrimPrefix(endpoint, from)
	}
	return endpoint
}

func oidcRequestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if value := r.Header.Get("X-Forwarded-Proto"); value != "" {
		scheme = strings.Split(value, ",")[0]
	}
	host := r.Host
	if value := r.Header.Get("X-Forwarded-Host"); value != "" {
		host = strings.Split(value, ",")[0]
	}
	return strings.TrimSpace(scheme) + "://" + strings.TrimSpace(host)
}
func oidcAppBase(settings repo.OIDCSettings, r *http.Request) string {
	if settings.PublicBaseURL != "" {
		return strings.TrimRight(settings.PublicBaseURL, "/")
	}
	return oidcRequestOrigin(r)
}
func oidcRedirectURI(settings repo.OIDCSettings, r *http.Request) string {
	return oidcAppBase(settings, r) + "/api/v1/auth/oidc/callback"
}

func randomURLToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func (h *AuthHandler) signOIDCState(value oidcState) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(h.Cfg.LocalAuthSecret))
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (h *AuthHandler) parseOIDCState(value string) (oidcState, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return oidcState{}, fmt.Errorf("invalid state")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcState{}, err
	}
	mac := hmac.New(sha256.New, []byte(h.Cfg.LocalAuthSecret))
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return oidcState{}, fmt.Errorf("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oidcState{}, err
	}
	var out oidcState
	err = json.Unmarshal(raw, &out)
	return out, err
}
func audienceContains(raw any, want string) bool {
	switch value := raw.(type) {
	case string:
		return value == want
	case []any:
		for _, item := range value {
			if item == want {
				return true
			}
		}
	}
	return false
}
