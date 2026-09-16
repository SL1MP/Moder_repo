package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwksTTL — как долго держим набор ключей издателя. Как в python-версии.
const jwksTTL = 15 * time.Minute

// refreshCooldown — минимальный интервал между внеплановыми перечитываниями
// JWKS. Внеплановое происходит, когда ключа с нужным kid в кэше нет: так
// выглядит штатная ротация ключей в Keycloak. Без этого python-версия до
// истечения TTL отвергает все токены, подписанные новым ключом — до четверти
// часа полной недоступности сервиса после ротации. Cooldown нужен, чтобы
// поток мусорных токенов с выдуманным kid не превратился в поток запросов к
// Keycloak.
const refreshCooldown = time.Minute

// maxJWKSBytes — потолок на ответ издателя. По этому адресу может стоять что
// угодно (прокси, балансировщик), и читать оттуда без ограничения нельзя.
const maxJWKSBytes = 1 << 20

// Doer — минимальный контракт HTTP-клиента, как в internal/registry.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// keySet — ключи издателя с временем загрузки.
type keySet struct {
	keys      map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	anonymous []any          // ключи без kid
	fetchedAt time.Time
}

// jwksCache — кэш ключей одного издателя.
type jwksCache struct {
	issuer string
	client Doer
	now    func() time.Time

	mu          sync.Mutex
	set         *keySet
	lastAttempt time.Time
}

func newJWKSCache(issuer string, client Doer, now func() time.Time) *jwksCache {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	return &jwksCache{issuer: strings.TrimRight(issuer, "/"), client: client, now: now}
}

// key возвращает ключ по kid. allowRefresh=false в повторном вызове, чтобы
// промах после перечитывания не зациклился.
func (c *jwksCache) key(ctx context.Context, kid string) (any, error) {
	set, err := c.current(ctx)
	if err != nil {
		return nil, err
	}
	if key, ok := lookup(set, kid); ok {
		return key, nil
	}

	// Промах по kid — скорее всего ротация. Перечитываем, если не читали
	// только что.
	refreshed, err := c.refreshIfAllowed(ctx)
	if err != nil {
		return nil, err
	}
	if refreshed != nil {
		if key, ok := lookup(refreshed, kid); ok {
			return key, nil
		}
	}
	return nil, &Error{Message: fmt.Sprintf(
		"Ключ подписи %q не найден в JWKS издателя %s — токен выпущен не этим realm'ом", kid, c.issuer)}
}

func lookup(set *keySet, kid string) (any, bool) {
	if kid != "" {
		key, ok := set.keys[kid]
		return key, ok
	}
	// Токен без kid: единственный ключ в наборе подходит однозначно, а при
	// нескольких угадывать нельзя — молчаливый перебор ключей означал бы, что
	// мы не знаем, чем именно проверили подпись.
	if len(set.anonymous) == 1 {
		return set.anonymous[0], true
	}
	if len(set.keys) == 1 && len(set.anonymous) == 0 {
		for _, key := range set.keys {
			return key, true
		}
	}
	return nil, false
}

func (c *jwksCache) current(ctx context.Context) (*keySet, error) {
	c.mu.Lock()
	if c.set != nil && c.now().Sub(c.set.fetchedAt) < jwksTTL {
		set := c.set
		c.mu.Unlock()
		return set, nil
	}
	c.mu.Unlock()
	return c.fetch(ctx)
}

func (c *jwksCache) refreshIfAllowed(ctx context.Context) (*keySet, error) {
	c.mu.Lock()
	if c.now().Sub(c.lastAttempt) < refreshCooldown {
		c.mu.Unlock()
		return nil, nil
	}
	c.mu.Unlock()
	return c.fetch(ctx)
}

func (c *jwksCache) fetch(ctx context.Context) (*keySet, error) {
	c.mu.Lock()
	c.lastAttempt = c.now()
	c.mu.Unlock()

	if c.issuer == "" {
		return nil, &Error{Message: "Не задан OIDC_ISSUER — проверка токенов невозможна"}
	}
	confURL := c.issuer + "/.well-known/openid-configuration"
	var conf struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := c.getJSON(ctx, confURL, "конфигурацию OIDC-издателя", &conf); err != nil {
		return nil, err
	}
	if conf.JWKSURI == "" {
		return nil, &Error{Message: "В конфигурации OIDC-издателя нет jwks_uri"}
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := c.getJSON(ctx, conf.JWKSURI, "JWKS издателя", &doc); err != nil {
		return nil, err
	}

	set := &keySet{keys: map[string]any{}, fetchedAt: c.now()}
	for _, k := range doc.Keys {
		// В наборе Keycloak лежат и ключи шифрования (use=enc): подписи ими
		// не проверяются, и попадание такого ключа в набор для подписи
		// означало бы отказ там, где рядом есть верный ключ.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		key, err := k.publicKey()
		if err != nil || key == nil {
			continue
		}
		if k.Kid != "" {
			set.keys[k.Kid] = key
		} else {
			set.anonymous = append(set.anonymous, key)
		}
	}
	if len(set.keys) == 0 && len(set.anonymous) == 0 {
		return nil, &Error{Message: fmt.Sprintf(
			"JWKS издателя %s не содержит ни одного пригодного ключа подписи", c.issuer)}
	}

	c.mu.Lock()
	c.set = set
	c.mu.Unlock()
	return set, nil
}

// getJSON читает JSON у издателя.
//
// Ответ разбирается с явной проверкой: по адресу издателя может стоять прокси
// или балансировщик, который отдаёт HTML-страницу с кодом 200. Без проверки
// это давало невнятную ошибку разбора вместо «издатель вернул не JSON».
func (c *jwksCache) getJSON(ctx context.Context, url, what string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return authErr(err, "Сборка запроса к OIDC-издателю (%s)", url)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return authErr(err, "OIDC-издатель недоступен (%s)", url)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return authErr(err, "Ответ OIDC-издателя не дочитан (%s)", url)
	}
	if resp.StatusCode >= 400 {
		return &Error{Message: fmt.Sprintf(
			"OIDC-издатель ответил %d на %s. Проверьте OIDC_ISSUER и что realm существует в Keycloak",
			resp.StatusCode, url)}
	}
	if err := json.Unmarshal(body, dst); err != nil {
		snippet := strings.ReplaceAll(string(body), "\n", " ")
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return &Error{Message: fmt.Sprintf("OIDC-издатель вернул не JSON на запрос %s: %s", what, snippet)}
	}
	return nil
}

// jwk — ключ из JWKS. Разбираются только RSA и EC P-256: остальное сервис
// всё равно не проверяет (см. закрытый список алгоритмов в jwt.go).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64uint(k.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31-1 {
			return nil, fmt.Errorf("экспонента ключа вне допустимого диапазона")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("кривая %q не поддерживается", k.Crv)
		}
		x, err := b64uint(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		if !pub.Curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("точка ключа не лежит на кривой")
		}
		return pub, nil
	}
	return nil, nil
}

func b64uint(v string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil {
		return nil, fmt.Errorf("значение ключа не декодируется из base64url: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("пустое значение в ключе")
	}
	return new(big.Int).SetBytes(raw), nil
}
