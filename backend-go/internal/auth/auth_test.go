package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"moderation/internal/domain"
)

// ---------------------------------------------------------------- инструменты

const testIssuerPath = "/realms/moderation"

// fakeIssuer — Keycloak на минималках: отдаёт openid-configuration и JWKS с
// теми ключами, которые ему положили. Нужен именно сервер, а не подмена
// разбора: проверять надо весь путь целиком, включая обнаружение jwks_uri.
type fakeIssuer struct {
	srv      *httptest.Server
	keys     atomic.Value // []jwk
	confHits atomic.Int64
	jwksHits atomic.Int64
	// jwksBody — если задано, отдаётся вместо нормального JSON (проверка
	// поведения, когда по адресу издателя стоит прокси с HTML-страницей).
	jwksBody atomic.Value
}

func newFakeIssuer(t *testing.T, keys ...jwk) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{}
	f.keys.Store(keys)
	mux := http.NewServeMux()
	mux.HandleFunc(testIssuerPath+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.confHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   f.issuer(),
			"jwks_uri": f.srv.URL + testIssuerPath + "/protocol/openid-connect/certs",
		})
	})
	mux.HandleFunc(testIssuerPath+"/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits.Add(1)
		if body, ok := f.jwksBody.Load().(string); ok && body != "" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": f.keys.Load().([]jwk)})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) issuer() string { return f.srv.URL + testIssuerPath }

func (f *fakeIssuer) setKeys(keys ...jwk) { f.keys.Store(keys) }

// signer — ключ, которым подписываются тестовые токены.
type signer struct {
	kid string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func newRSASigner(t *testing.T, kid string) *signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("генерация RSA-ключа: %v", err)
	}
	return &signer{kid: kid, rsa: key}
}

func newECSigner(t *testing.T, kid string) *signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("генерация EC-ключа: %v", err)
	}
	return &signer{kid: kid, ec: key}
}

func (s *signer) jwk() jwk {
	if s.rsa != nil {
		return jwk{
			Kty: "RSA", Kid: s.kid, Use: "sig",
			N: base64.RawURLEncoding.EncodeToString(s.rsa.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.rsa.E)).Bytes()),
		}
	}
	return jwk{
		Kty: "EC", Kid: s.kid, Use: "sig", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(s.ec.X.FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(s.ec.Y.FillBytes(make([]byte, 32))),
	}
}

func (s *signer) sign(t *testing.T, alg string, payload map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": alg, "typ": "JWT"}
	if s.kid != "" {
		header["kid"] = s.kid
	}
	input := encodeSegment(t, header) + "." + encodeSegment(t, payload)

	var sig []byte
	var err error
	switch alg {
	case algRS256:
		sum := sha256.Sum256([]byte(input))
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsa, crypto.SHA256, sum[:])
	case algES256:
		sum := sha256.Sum256([]byte(input))
		var r, ss *big.Int
		r, ss, err = ecdsa.Sign(rand.Reader, s.ec, sum[:])
		if err == nil {
			sig = append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
		}
	default:
		t.Fatalf("тест не умеет подписывать %s", alg)
	}
	if err != nil {
		t.Fatalf("подпись тестового токена: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func encodeSegment(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("сборка сегмента токена: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// mapper — маппинг групп как в .env.example.
type mapper struct{}

func (mapper) RoleForGroup(group string) string {
	switch group {
	case "moderation-admin":
		return "admin"
	case "moderation-devsecops":
		return "devsecops"
	case "moderation-legal":
		return "legal"
	case "moderation-developer":
		return "developer"
	}
	return ""
}

var fixedNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func newTestVerifier(f *fakeIssuer, tweak func(*Settings)) *Verifier {
	settings := Settings{
		Issuer:          f.issuer(),
		AcceptedIssuers: []string{f.issuer()},
		Mapper:          mapper{},
	}
	if tweak != nil {
		tweak(&settings)
	}
	return NewVerifier(settings, f.srv.Client(), func() time.Time { return fixedNow })
}

func validPayload(issuer string) map[string]any {
	return map[string]any{
		"iss":                issuer,
		"sub":                "8f1c-uuid",
		"preferred_username": "ivanov",
		"email":              "ivanov@example.com",
		"name":               "Иван Иванов",
		"exp":                fixedNow.Add(time.Hour).Unix(),
		"iat":                fixedNow.Add(-time.Minute).Unix(),
		"realm_access":       map[string]any{"roles": []any{"moderation-legal", "offline_access"}},
	}
}

// ---------------------------------------------------------------- проверки

func TestDecodeOIDCToken(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	claims, err := v.Decode(context.Background(), s.sign(t, algRS256, validPayload(f.issuer())))
	if err != nil {
		t.Fatalf("токен должен приниматься: %v", err)
	}
	if claims.Subject != "8f1c-uuid" || claims.Username != "ivanov" {
		t.Fatalf("claims разобраны неверно: %+v", claims)
	}
	if claims.FullName != "Иван Иванов" || claims.Email != "ivanov@example.com" {
		t.Fatalf("профиль разобран неверно: %+v", claims)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "legal" {
		t.Fatalf("ожидалась роль legal, получено %v", claims.Roles)
	}
	if claims.IsService {
		t.Fatal("пользователь с email не сервисная учётка")
	}
}

// Кэш обязан работать: без него каждый запрос к API превращается в два
// запроса к Keycloak, и он становится точкой отказа на каждом вызове.
func TestJWKSCached(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)
	token := s.sign(t, algRS256, validPayload(f.issuer()))

	for i := 0; i < 5; i++ {
		if _, err := v.Decode(context.Background(), token); err != nil {
			t.Fatalf("прогон %d: %v", i, err)
		}
	}
	if got := f.jwksHits.Load(); got != 1 {
		t.Fatalf("JWKS должен читаться один раз, прочитан %d раз", got)
	}
}

// Ротация ключа в Keycloak: старый kid из кэша, токен подписан новым.
// Python-версия здесь отвергает токены до истечения TTL (15 минут) — это
// расхождение намеренное, см. комментарий к refreshCooldown.
func TestJWKSRefreshedOnUnknownKid(t *testing.T) {
	old := newRSASigner(t, "key-old")
	f := newFakeIssuer(t, old.jwk())
	v := newTestVerifier(f, nil)
	if _, err := v.Decode(context.Background(), old.sign(t, algRS256, validPayload(f.issuer()))); err != nil {
		t.Fatalf("первый токен: %v", err)
	}

	fresh := newRSASigner(t, "key-new")
	f.setKeys(old.jwk(), fresh.jwk())

	// Внеплановое перечитывание разрешено не чаще раза в минуту — сдвигаем часы.
	v.now = func() time.Time { return fixedNow.Add(2 * time.Minute) }
	v.jwks.now = v.now

	payload := validPayload(f.issuer())
	payload["exp"] = fixedNow.Add(time.Hour).Unix()
	if _, err := v.Decode(context.Background(), fresh.sign(t, algRS256, payload)); err != nil {
		t.Fatalf("токен, подписанный новым ключом, должен приниматься после перечитывания JWKS: %v", err)
	}
	if got := f.jwksHits.Load(); got != 2 {
		t.Fatalf("ожидалось ровно одно перечитывание JWKS, всего чтений %d", got)
	}
}

// Поток токенов с выдуманным kid не должен превращаться в поток запросов к
// Keycloak — иначе это способ положить издателя через наш API.
func TestUnknownKidRefreshThrottled(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	bogus := newRSASigner(t, "kid-выдуман")
	for i := 0; i < 10; i++ {
		if _, err := v.Decode(context.Background(), bogus.sign(t, algRS256, validPayload(f.issuer()))); err == nil {
			t.Fatal("токен с неизвестным kid не должен приниматься")
		}
	}
	if got := f.jwksHits.Load(); got > 2 {
		t.Fatalf("десять мусорных токенов дали %d чтений JWKS — throttling не работает", got)
	}
}

func TestDecodeRejects(t *testing.T) {
	s := newRSASigner(t, "key-1")
	other := newRSASigner(t, "key-1") // тот же kid, другой ключ
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	expired := validPayload(f.issuer())
	expired["exp"] = fixedNow.Add(-time.Hour).Unix()

	noExp := validPayload(f.issuer())
	delete(noExp, "exp")

	future := validPayload(f.issuer())
	future["nbf"] = fixedNow.Add(time.Hour).Unix()

	alien := validPayload("https://evil.example.com/realms/moderation")

	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"чужой ключ", other.sign(t, algRS256, validPayload(f.issuer())), "не прошла проверку"},
		{"истёкший", s.sign(t, algRS256, expired), "Срок действия"},
		{"без exp", s.sign(t, algRS256, noExp), "нет срока действия"},
		{"ещё не действует", s.sign(t, algRS256, future), "не вступил в силу"},
		{"чужой издатель", s.sign(t, algRS256, alien), "не в списке доверенных"},
		{"не токен", "просто строка", "неверный формат"},
		{"две части", "aaa.bbb", "неверный формат"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Decode(context.Background(), tc.token)
			if err == nil {
				t.Fatal("токен должен быть отвергнут")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("сообщение должно объяснять причину (%q), получено: %v", tc.want, err)
			}
		})
	}
}

// Классическая подделка: подделыватель берёт публичный ключ издателя (он
// лежит в открытом доступе по /certs), подписывает им токен как HS256 и
// пишет alg=HS256 в заголовок. Реализация, которая выбирает алгоритм по
// заголовку токена, такую подделку принимает.
func TestAlgConfusionRejected(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	payload := validPayload(f.issuer())
	payload["realm_access"] = map[string]any{"roles": []any{"moderation-admin"}}
	header := map[string]string{"alg": algHS256, "typ": "JWT", "kid": "key-1"}
	input := encodeSegment(t, header) + "." + encodeSegment(t, payload)
	mac := hmac.New(sha256.New, s.rsa.N.Bytes()) // «секрет» — публичный модуль ключа
	mac.Write([]byte(input))
	forged := input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if _, err := v.Decode(context.Background(), forged); err == nil {
		t.Fatal("подмена алгоритма на HS256 должна отвергаться")
	}

	// Выше подделка не прошла бы и без списка допустимых алгоритмов — просто
	// потому, что из JWKS пришёл ключ RSA, а не общий секрет. Проверяем сам
	// список отдельно: он и есть та защита, которая обязана сработать первой.
	parsed, err := parseJWT(forged)
	if err != nil {
		t.Fatalf("разбор подделки: %v", err)
	}
	if err := parsed.verifySignature(s.rsa.N.Bytes(), []string{algRS256, algRS512, algES256}); err == nil {
		t.Fatal("HS256 не входит в список допустимых для токенов издателя — подпись не должна проверяться")
	} else if !strings.Contains(err.Error(), "не принимается") {
		t.Fatalf("отказ должен ссылаться на список алгоритмов, получено: %v", err)
	}
}

// alg=none — вторая классическая подделка: подписи нет вовсе.
func TestAlgNoneRejected(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	header := map[string]string{"alg": "none", "typ": "JWT", "kid": "key-1"}
	token := encodeSegment(t, header) + "." + encodeSegment(t, validPayload(f.issuer())) + "."
	if _, err := v.Decode(context.Background(), token); err == nil {
		t.Fatal("alg=none должен отвергаться")
	}
}

func TestES256Accepted(t *testing.T) {
	s := newECSigner(t, "ec-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	if _, err := v.Decode(context.Background(), s.sign(t, algES256, validPayload(f.issuer()))); err != nil {
		t.Fatalf("токен ES256 должен приниматься: %v", err)
	}
}

// Браузер ходит на внешний адрес Keycloak, сервис — на внутренний. Токен от
// SPA приходит с внешним iss, и он обязан приниматься: это самая частая
// причина «вход работает, а API отвечает 401».
func TestBothIssuersAccepted(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	const public = "https://moderated-repo.example.com/realms/moderation"
	v := newTestVerifier(f, func(st *Settings) {
		st.AcceptedIssuers = []string{f.issuer(), public}
	})

	if _, err := v.Decode(context.Background(), s.sign(t, algRS256, validPayload(public))); err != nil {
		t.Fatalf("токен с внешним издателем должен приниматься: %v", err)
	}
}

// По адресу издателя может стоять прокси, отдающий HTML с кодом 200.
// Сообщение должно называть причину, а не «ошибка разбора JSON».
func TestIssuerReturnsHTML(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	f.jwksBody.Store("<html><body>502 Bad Gateway</body></html>")
	v := newTestVerifier(f, nil)

	_, err := v.Decode(context.Background(), s.sign(t, algRS256, validPayload(f.issuer())))
	if err == nil || !strings.Contains(err.Error(), "не JSON") {
		t.Fatalf("ожидалось понятное сообщение про не-JSON, получено: %v", err)
	}
}

// Ключи шифрования (use=enc) не годятся для проверки подписи: если брать их
// наравне с подписными, то при совпадении kid проверка провалится там, где
// рядом лежит верный ключ.
func TestEncryptionKeysIgnored(t *testing.T) {
	s := newRSASigner(t, "key-1")
	enc := newRSASigner(t, "key-enc").jwk()
	enc.Use = "enc"
	f := newFakeIssuer(t, enc, s.jwk())
	v := newTestVerifier(f, nil)

	if _, err := v.Decode(context.Background(), s.sign(t, algRS256, validPayload(f.issuer()))); err != nil {
		t.Fatalf("подписной ключ должен находиться рядом с ключом шифрования: %v", err)
	}
}

func TestRolesFromAllClaimShapes(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	payload := validPayload(f.issuer())
	// Keycloak отдаёт группы с ведущим слэшем.
	payload["groups"] = []any{"/moderation-admin", "/прочая-группа"}
	payload["realm_access"] = map[string]any{"roles": []any{"moderation-legal"}}
	payload["resource_access"] = map[string]any{
		"moderation-web": map[string]any{"roles": []any{"moderation-devsecops"}},
		"account":        map[string]any{"roles": []any{"view-profile"}},
	}

	claims, err := v.Decode(context.Background(), s.sign(t, algRS256, payload))
	if err != nil {
		t.Fatalf("токен должен приниматься: %v", err)
	}
	want := []string{"admin", "devsecops", "legal"}
	if strings.Join(claims.Roles, ",") != strings.Join(want, ",") {
		t.Fatalf("роли должны собираться из всех трёх мест: %v", claims.Roles)
	}
	if PrimaryRole(claims.Roles) != "admin" {
		t.Fatalf("старшая роль должна быть admin, получено %q", PrimaryRole(claims.Roles))
	}
}

// Учётка без единой известной группы входит, но без прав: отказ должен
// приходить от проверки прав с внятным текстом, а не выглядеть как
// «сломался вход».
func TestUnknownGroupsGiveNoRoles(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	payload := validPayload(f.issuer())
	payload["realm_access"] = map[string]any{"roles": []any{"default-roles-moderation", "offline_access"}}
	claims, err := v.Decode(context.Background(), s.sign(t, algRS256, payload))
	if err != nil {
		t.Fatalf("токен должен приниматься: %v", err)
	}
	if len(claims.Roles) != 0 {
		t.Fatalf("ролей быть не должно, получено %v", claims.Roles)
	}
}

func TestServiceAccountDetected(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, nil)

	payload := validPayload(f.issuer())
	delete(payload, "email")
	delete(payload, "preferred_username")
	payload["client_id"] = "ci-bot"
	claims, err := v.Decode(context.Background(), s.sign(t, algRS256, payload))
	if err != nil {
		t.Fatalf("токен сервисной учётки должен приниматься: %v", err)
	}
	if !claims.IsService || claims.Username != "ci-bot" {
		t.Fatalf("сервисная учётка разобрана неверно: %+v", claims)
	}
}

// ---------------------------------------------------------------- локальный вход

func TestLocalTokenRoundTrip(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, func(st *Settings) {
		st.LocalAuthEnabled = true
		st.LocalAuthSecret = "секрет-для-теста"
		st.LocalTokenTTL = 8 * time.Hour
	})

	user := testUser("ci-bot", "devsecops")
	token, ttl, err := v.IssueLocalToken(user)
	if err != nil {
		t.Fatalf("выпуск локального токена: %v", err)
	}
	if ttl != 8*3600 {
		t.Fatalf("срок жизни должен быть в секундах, получено %d", ttl)
	}

	claims, err := v.Decode(context.Background(), token)
	if err != nil {
		t.Fatalf("свой же токен должен приниматься: %v", err)
	}
	if claims.Subject != "local:ci-bot" || claims.Username != "ci-bot" {
		t.Fatalf("claims локального токена: %+v", claims)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "devsecops" {
		t.Fatalf("роли берутся из токена: %v", claims.Roles)
	}
	if !claims.IsService {
		t.Fatal("локальный токен — всегда сервисная учётка")
	}
	// За JWKS ходить незачем: локальный токен проверяется своим секретом.
	if f.jwksHits.Load() != 0 {
		t.Fatal("локальный токен не должен приводить к запросу в Keycloak")
	}
}

// Выключенный LOCAL_AUTH_ENABLED обязан закрывать и выпуск, и приём: иначе
// токен, выпущенный до выключения флага, продолжал бы работать.
func TestLocalTokenRejectedWhenDisabled(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	issuing := newTestVerifier(f, func(st *Settings) {
		st.LocalAuthEnabled = true
		st.LocalAuthSecret = "секрет"
		st.LocalTokenTTL = time.Hour
	})
	token, _, err := issuing.IssueLocalToken(testUser("ci-bot", "admin"))
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}

	closed := newTestVerifier(f, func(st *Settings) {
		st.LocalAuthEnabled = false
		st.LocalAuthSecret = "секрет"
	})
	if _, err := closed.Decode(context.Background(), token); err == nil {
		t.Fatal("при LOCAL_AUTH_ENABLED=false локальный токен не принимается")
	}
	if _, _, err := closed.IssueLocalToken(testUser("ci-bot", "admin")); err == nil {
		t.Fatal("при LOCAL_AUTH_ENABLED=false токен не выпускается")
	}
}

func TestLocalTokenWrongSecretRejected(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	issuing := newTestVerifier(f, func(st *Settings) {
		st.LocalAuthEnabled = true
		st.LocalAuthSecret = "секрет-один"
		st.LocalTokenTTL = time.Hour
	})
	token, _, _ := issuing.IssueLocalToken(testUser("ci-bot", "admin"))

	other := newTestVerifier(f, func(st *Settings) {
		st.LocalAuthEnabled = true
		st.LocalAuthSecret = "секрет-другой"
	})
	if _, err := other.Decode(context.Background(), token); err == nil {
		t.Fatal("токен, подписанный другим секретом, не принимается")
	}
}

func TestLocalTokenExpires(t *testing.T) {
	s := newRSASigner(t, "key-1")
	f := newFakeIssuer(t, s.jwk())
	v := newTestVerifier(f, func(st *Settings) {
		st.LocalAuthEnabled = true
		st.LocalAuthSecret = "секрет"
		st.LocalTokenTTL = time.Hour
	})
	token, _, _ := v.IssueLocalToken(testUser("ci-bot", "admin"))

	v.now = func() time.Time { return fixedNow.Add(2 * time.Hour) }
	if _, err := v.Decode(context.Background(), token); err == nil {
		t.Fatal("истёкший локальный токен не принимается")
	}
}

// ---------------------------------------------------------------- пароли

// Хеши сняты с той же библиотеки, которой пользуется python-версия (bcrypt),
// а не сгенерированы этим же кодом: проверяется совместимость с уже
// записанными в базу хешами, а не то, что реализация согласована сама с собой.
func TestVerifyPasswordAgainstPythonHashes(t *testing.T) {
	const hash = "$2b$04$4LRBQMJxRSq5Imqlsu7zTOVZz3UyiWiL.jm5W8p3S29Tjmg7g..H6"
	if !VerifyPassword("service-secret-42", ptr(hash)) {
		t.Fatal("хеш, записанный python-версией, должен приниматься")
	}
	if VerifyPassword("service-secret-43", ptr(hash)) {
		t.Fatal("неверный пароль принят")
	}
}

// Пароль длиннее 72 байт обрезается ровно так же, как это делает
// python-версия (обрезка по БАЙТАМ, а не по символам, — она может разрезать
// многобайтовый символ пополам, и хеш всё равно обязан совпасть).
func TestLongPasswordTruncatedLikePython(t *testing.T) {
	const hash = "$2b$04$ZVjt0cyZcjqZpgcPp46LrOVB.8Hy7ePLYm5hghFcQec2u31kCX34m"
	password := "x" + strings.Repeat("☭", 30) // 91 байт, обрезка приходится на середину символа
	if len([]byte(password)) <= bcryptMaxBytes {
		t.Fatalf("тест бессмыслен: пароль %d байт", len([]byte(password)))
	}
	if !VerifyPassword(password, ptr(hash)) {
		t.Fatal("длинный пароль должен обрезаться так же, как в python-версии")
	}
}

// Пустой хеш означает «вход по паролю не настроен», а не «подойдёт любой».
func TestEmptyPasswordHashDeniesAccess(t *testing.T) {
	if VerifyPassword("", nil) || VerifyPassword("", ptr("")) || VerifyPassword("что угодно", ptr("")) {
		t.Fatal("учётка без пароля не должна пускать")
	}
}

// Пароль длиннее 72 байт должен заводиться так же, как в python-версии:
// без обрезки x/crypto/bcrypt отказывается его хешировать вовсе.
func TestHashLongPassword(t *testing.T) {
	password := "x" + strings.Repeat("☭", 30)
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("длинный пароль должен хешироваться: %v", err)
	}
	if !VerifyPassword(password, &hash) {
		t.Fatal("свой же хеш длинного пароля должен проверяться")
	}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("пароль-сервисной-учётки")
	if err != nil {
		t.Fatalf("хеширование: %v", err)
	}
	if !VerifyPassword("пароль-сервисной-учётки", &hash) {
		t.Fatal("свой же хеш должен проверяться")
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("формат хеша должен быть bcrypt: %q", hash)
	}
}

func ptr(s string) *string { return &s }

func testUser(username string, roles ...string) *domain.User {
	return &domain.User{ID: 7, Username: username, Roles: roles, IsService: true, IsActive: true}
}
