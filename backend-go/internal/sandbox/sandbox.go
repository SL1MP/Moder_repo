// Package sandbox — отправка артефакта в песочницу и разбор её вердикта.
//
// Порт шага `.send_to_sandbox` из CI-версии (GitLab CI template). Контракт
// взят оттуда дословно, потому что это единственный достоверный источник по
// API песочницы, который у нас есть:
//
//	POST {SANDBOX_URL}/api/v1/scan/checkFile
//	     ?file_name=…&short_result=…&async_result=false&priority=…
//	     X-API-Key: {SANDBOX_TOKEN}
//	     Content-Type: application/gzip
//	     <тело — байты архива>
//
//	{"data": {"scan_id": "…", "result": {"verdict": "CLEAN|DANGEROUS|UNWANTED"}}}
//
// Отличие от CI-версии: она отправляет tar.gz всего проекта, собранный
// джобой. Здесь отправляется ровно тот файл, который конвейер скачал из
// реестра, — он и есть предмет модерации, и пересобирать его в другой архив
// значило бы проверять не то, что будет опубликовано.
//
// Чего здесь намеренно НЕТ (решение пользователя): заведения задачи в YouTrack
// и отправки метрик в SRE. В CI это компенсировало отсутствие места, где
// решение принимает человек; в сервисе такое место есть — очередь DevSecOps.
//
// Разбор ответа устроен защитно. Достоверно известны только два поля —
// `data.result.verdict` и `data.scan_id`; схему списка находок CI-шаблон не
// раскрывает (он отдаёт её отдельному скрипту generate_report.py). Поэтому
// находки разбираются по нескольким распространённым ключам, а полный ответ
// целиком кладётся в отчёт: даже если раскладка находок окажется иной,
// DevSecOps увидит всё, что прислала песочница, а не «находок нет».
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Вердикты песочницы. Значения — из CI-шаблона (сравнение `$status` с
// 'DANGEROUS', 'CLEAN', 'UNWANTED').
const (
	VerdictClean     = "CLEAN"
	VerdictDangerous = "DANGEROUS"
	VerdictUnwanted  = "UNWANTED"
)

// Detection — одна находка песочницы.
type Detection struct {
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Severity string `json:"severity,omitempty"`
	Details  string `json:"details,omitempty"`
}

// Result — разобранный ответ песочницы.
//
// Raw — ответ целиком, как его прислала песочница. Он попадает в отчёт:
// вердикт отвечает на вопрос «публиковать ли», а Raw — на вопрос «почему»,
// и второй вопрос задают ровно тогда, когда ответ на первый кому-то не нравится.
type Result struct {
	Verdict    string
	ScanID     string
	TaskURL    string
	Detections []Detection
	Raw        json.RawMessage
	Duration   time.Duration
}

// Known — знаком ли нам этот вердикт. Незнакомый вердикт не «чисто»: шаг
// обязан позвать DevSecOps, а не пропустить пакет.
func (r Result) Known() bool {
	switch r.Verdict {
	case VerdictClean, VerdictDangerous, VerdictUnwanted:
		return true
	}
	return false
}

// Client — контракт песочницы. Интерфейс, а не структура: шаг конвейера не
// должен знать, ходит ли он по сети или получает ответ от заглушки в тесте.
type Client interface {
	// Available — настроена ли песочница. false означает «проверить нечем»,
	// и это не то же самое, что «чисто».
	Available() bool
	// Endpoint — адрес песочницы, для сообщений и отчёта.
	Endpoint() string
	// Check отправляет байты артефакта и возвращает вердикт.
	Check(ctx context.Context, filename string, payload []byte) (Result, error)
}

// Config — параметры песочницы.
type Config struct {
	// BaseURL — SANDBOX_URL из CI-версии. Пустой означает «песочница не
	// настроена»: клиент собирается, но Available()=false.
	BaseURL string
	// Token — SEC_TOKEN, уходит заголовком X-API-Key.
	Token string
	// Priority — приоритет задачи в очереди песочницы (в CI — 3).
	Priority int
	// ShortResult — короткий ответ вместо полного (в CI — true). Полный ответ
	// содержательнее для отчёта, но тяжелее и дольше собирается.
	ShortResult bool
	// Timeout — потолок на один запрос. Песочница запускает образец
	// по-настоящему, поэтому потолок минутный, а не секундный.
	Timeout time.Duration
	// InsecureTLS — принимать самоподписанный сертификат (в CI это `curl -k`).
	// Отдельным флагом, а не молча: «-k» в шаблоне легко не заметить, а
	// выключенная проверка сертификата обязана быть видимым решением.
	InsecureTLS bool
	// HTTPClient подменяется в тестах.
	HTTPClient *http.Client
}

type client struct {
	cfg  Config
	http *http.Client
}

// New собирает клиент. Ошибки нет намеренно: ненастроенная песочница — не
// повод не подняться сервису, это повод шагу сказать «проверить нечем» и
// позвать DevSecOps.
func New(cfg Config) Client {
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.Priority <= 0 {
		cfg.Priority = 3 // значение CI-шаблона
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Minute
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
		if cfg.InsecureTLS {
			httpClient.Transport = insecureTransport()
		}
	}
	return &client{cfg: cfg, http: httpClient}
}

func (c *client) Available() bool { return c.cfg.BaseURL != "" }

func (c *client) Endpoint() string { return c.cfg.BaseURL }

func (c *client) Check(ctx context.Context, filename string, payload []byte) (Result, error) {
	if !c.Available() {
		return Result{}, fmt.Errorf("адрес песочницы не задан (SANDBOX_URL)")
	}
	if len(payload) == 0 {
		return Result{}, fmt.Errorf("пустой артефакт: отправлять в песочницу нечего")
	}

	query := url.Values{}
	query.Set("file_name", filename)
	query.Set("short_result", strconv.FormatBool(c.cfg.ShortResult))
	// async_result=false — ждём вердикт в этом же ответе. Асинхронный режим
	// означал бы опрос по scan_id, а конвейер и так выполняется в фоне:
	// пакету всё равно, ждёт его воркер или опрашивает.
	query.Set("async_result", "false")
	query.Set("priority", strconv.Itoa(c.cfg.Priority))
	endpoint := c.cfg.BaseURL + "/api/v1/scan/checkFile?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, fmt.Errorf("сборка запроса к песочнице: %w", err)
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("X-API-Key", c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	// Content-Type CI-шаблона — application/gzip, но он отправлял именно
	// tar.gz. Мы отправляем артефакт как есть (.whl, .tgz, .jar, .nupkg), и
	// врать про тип содержимого не нужно: песочница определяет формат сама, а
	// octet-stream — честное «двоичный файл».
	req.Header.Set("Content-Type", "application/octet-stream")

	started := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("запрос к песочнице %s: %w", c.cfg.BaseURL, err)
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return Result{}, fmt.Errorf("чтение ответа песочницы: %w", err)
	}
	if resp.StatusCode >= 400 {
		return Result{}, fmt.Errorf("песочница ответила %d: %s", resp.StatusCode, excerpt(body))
	}

	result, err := parse(body)
	if err != nil {
		return Result{}, err
	}
	result.Duration = time.Since(started)
	if result.ScanID != "" {
		result.TaskURL = c.cfg.BaseURL + "/tasks/" + result.ScanID
	}
	return result, nil
}

// --------------------------------------------------------------------------- разбор ответа

// envelope — достоверно известная часть ответа (из CI-шаблона:
// `jq -r '.data.result.verdict'` и `jq -r '.data.scan_id'`).
type envelope struct {
	Data struct {
		ScanID json.RawMessage `json:"scan_id"`
		Result json.RawMessage `json:"result"`
	} `json:"data"`
}

func parse(body []byte) (Result, error) {
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Result{}, fmt.Errorf("ответ песочницы не разобран как JSON: %w (%s)", err, excerpt(body))
	}
	if len(env.Data.Result) == 0 {
		return Result{}, fmt.Errorf("в ответе песочницы нет data.result: %s", excerpt(body))
	}

	var inner map[string]json.RawMessage
	if err := json.Unmarshal(env.Data.Result, &inner); err != nil {
		return Result{}, fmt.Errorf("data.result песочницы не разобран: %w (%s)", err, excerpt(body))
	}

	result := Result{ScanID: scalar(env.Data.ScanID), Raw: body}
	if raw, ok := inner["verdict"]; ok {
		result.Verdict = strings.ToUpper(strings.TrimSpace(scalar(raw)))
	}
	result.Detections = detections(inner)
	return result, nil
}

// detectionKeys — ключи, под которыми песочница может отдавать список находок.
// Схему CI-шаблон не раскрывает, поэтому смотрим на все распространённые
// варианты; какой бы ни подошёл, полный ответ всё равно уходит в отчёт.
var detectionKeys = []string{"detections", "threats", "malware", "verdicts", "detects"}

func detections(inner map[string]json.RawMessage) []Detection {
	var out []Detection
	for _, key := range detectionKeys {
		raw, ok := inner[key]
		if !ok {
			continue
		}
		out = append(out, parseDetections(raw)...)
	}
	// Одна и та же находка может прийти сразу под двумя ключами (например, и
	// в threats, и в detections) — показывать её дважды незачем.
	return dedupe(out)
}

func parseDetections(raw json.RawMessage) []Detection {
	// Список объектов — основной ожидаемый вид.
	var objects []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &objects); err == nil {
		out := make([]Detection, 0, len(objects))
		for _, obj := range objects {
			d := Detection{
				Name:     firstOf(obj, "name", "detect", "signature", "rule", "title", "id"),
				Type:     firstOf(obj, "type", "category", "class", "kind"),
				Severity: strings.ToLower(firstOf(obj, "severity", "level", "risk", "danger_level")),
				Details:  firstOf(obj, "details", "description", "message", "info", "comment"),
			}
			if d.Name == "" && d.Details == "" && d.Type == "" {
				continue
			}
			out = append(out, d)
		}
		return out
	}
	// Список строк — тоже встречается: «нашли вот это», без подробностей.
	var names []string
	if err := json.Unmarshal(raw, &names); err == nil {
		out := make([]Detection, 0, len(names))
		for _, name := range names {
			if name = strings.TrimSpace(name); name != "" {
				out = append(out, Detection{Name: name})
			}
		}
		return out
	}
	return nil
}

// firstOf — первое непустое значение из перечисленных ключей.
func firstOf(obj map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		if raw, ok := obj[key]; ok {
			if value := strings.TrimSpace(scalar(raw)); value != "" {
				return value
			}
		}
	}
	return ""
}

// scalar приводит значение JSON к строке. Песочница может отдать scan_id и
// числом, и строкой; разбирать это как строго строку значило бы терять
// идентификатор задачи из-за типа поля.
func scalar(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return strconv.FormatBool(b)
	}
	return strings.TrimSpace(string(raw))
}

func dedupe(in []Detection) []Detection {
	seen := make(map[Detection]bool, len(in))
	out := make([]Detection, 0, len(in))
	for _, d := range in {
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func excerpt(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		return text[:300] + "…"
	}
	if text == "" {
		return "пустой ответ"
	}
	return text
}
