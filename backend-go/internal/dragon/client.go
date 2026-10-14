// Package dragon integrates the moderation pipeline with Dragon archive runs.
//
// Dragon executes informational scanners, but it never decides whether a
// package may be published. Moderation uploads the exact bytes saved by
// DownloadStep and records the run returned by Dragon.
package dragon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Artifact is the immutable archive uploaded to Dragon.
type Artifact struct {
	Manager   string
	Name      string
	Version   string
	Filename  string
	SHA256    string
	SizeBytes int64
	Payload   []byte
}

// Request starts one archive run.
type Request struct {
	PipelineID   string
	RepositoryID string
	ExternalID   string
	Artifact     Artifact
	Publish      bool
	Priority     int
}

// LogLine and Job mirror the status response currently returned by Dragon.
// Logs are parsed in memory for counters; the pipeline persists only compact
// job summaries and links, not the potentially large raw logs.
type LogLine struct {
	Class string `json:"c"`
	Text  string `json:"t"`
}

type Job struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Stage           string    `json:"stage"`
	Scanner         string    `json:"scanner"`
	Status          string    `json:"status"`
	Duration        string    `json:"dur"`
	AllowFailure    bool      `json:"allow_failure"`
	TestID          string    `json:"testId"`
	Log             []LogLine `json:"log"`
	ReportSize      int64     `json:"report_size"`
	ReportDeleted   bool      `json:"report_deleted"`
	LogDeleted      bool      `json:"log_deleted"`
	Runner          string    `json:"runner"`
	ArtifactSize    int64     `json:"artifact_size"`
	ArtifactDeleted bool      `json:"artifact_deleted"`
}

// FindingSummary is deliberately split by scanner family. A Semgrep finding
// is not automatically a package vulnerability, and a Gitleaks secret is not
// one either. Counts are extracted from the status logs only for display.
type FindingSummary struct {
	Vulnerabilities int `json:"vulnerabilities"`
	Secrets         int `json:"secrets"`
	CodeFindings    int `json:"code_findings"`
	Total           int `json:"total"`
}

// Result contains both the archive acceptance response and the terminal
// status. It can also be returned together with an error after Dragon has
// accepted the archive, allowing the pipeline to show the run URL without
// blocking package publication.
type Result struct {
	RunID            string         `json:"id"`
	Status           string         `json:"status"`
	Done             bool           `json:"done"`
	Success          bool           `json:"success"`
	ArtifactVerified bool           `json:"artifact_verified"`
	RunURL           string         `json:"run_url"`
	StatusURL        string         `json:"status_url"`
	ArchiveSHA256    string         `json:"sha256"`
	ArchiveFormat    string         `json:"format"`
	ArchiveFiles     int            `json:"files"`
	ArchiveBytes     int64          `json:"bytes"`
	ArchiveSkipped   int            `json:"skipped"`
	Pipeline         string         `json:"pipeline"`
	Repo             string         `json:"repo"`
	RepositoryID     string         `json:"repository_id"`
	Branch           string         `json:"branch"`
	SHA              string         `json:"sha"`
	Author           string         `json:"author"`
	Message          string         `json:"msg"`
	Error            string         `json:"error"`
	Event            string         `json:"event"`
	Source           string         `json:"source"`
	Archive          string         `json:"archive"`
	Name             string         `json:"name"`
	StartedBy        string         `json:"started_by"`
	Published        bool           `json:"published"`
	Publish          bool           `json:"publish"`
	Priority         int            `json:"priority"`
	Stages           []string       `json:"stages"`
	Jobs             []Job          `json:"jobs"`
	Variables        map[string]any `json:"variables"`
	OakshieldURL     string         `json:"oakshield_url"`
	Findings         FindingSummary `json:"findings"`
}

// Scanner is the pipeline-facing contract. Tests use a fake; production uses
// Client below.
type Scanner interface {
	Scan(ctx context.Context, req Request) (Result, error)
}

type Config struct {
	BaseURL      string
	Token        string
	PollInterval time.Duration
	Timeout      time.Duration
	HTTPClient   *http.Client
}

type Client struct {
	baseURL      string
	token        string
	pollInterval time.Duration
	timeout      time.Duration
	http         *http.Client
}

func New(cfg Config) *Client {
	poll := cfg.PollInterval
	if poll <= 0 {
		poll = 5 * time.Second
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 25 * time.Minute
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		// The request context owns the total deadline. A fixed one-minute client
		// timeout would abort valid uploads of large package archives.
		httpClient = &http.Client{}
	}
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		token: strings.TrimSpace(cfg.Token), pollInterval: poll,
		timeout: timeout, http: httpClient,
	}
}

type createResponse struct {
	ID        string `json:"id"`
	StatusURL string `json:"status_url"`
	RunURL    string `json:"run_url"`
	SHA256    string `json:"sha256"`
	Format    string `json:"format"`
	Files     int    `json:"files"`
	Bytes     int64  `json:"bytes"`
	Skipped   int    `json:"skipped"`
}

type statusResponse struct {
	ID           string         `json:"id"`
	Status       string         `json:"status"`
	Pipeline     string         `json:"pipeline"`
	Repo         string         `json:"repo"`
	RepositoryID string         `json:"repository_id"`
	Branch       string         `json:"branch"`
	SHA          string         `json:"sha"`
	Author       string         `json:"author"`
	Message      string         `json:"msg"`
	Error        string         `json:"error"`
	Event        string         `json:"event"`
	Source       string         `json:"source"`
	Archive      string         `json:"archive"`
	Name         string         `json:"name"`
	StartedBy    string         `json:"started_by"`
	Published    bool           `json:"published"`
	Publish      bool           `json:"publish"`
	Priority     int            `json:"priority"`
	Stages       []string       `json:"stages"`
	Jobs         []Job          `json:"jobs"`
	Variables    map[string]any `json:"variables"`
	OakshieldURL string         `json:"oakshield_url"`
}

func (c *Client) Scan(ctx context.Context, req Request) (Result, error) {
	if c.baseURL == "" {
		return Result{}, fmt.Errorf("DRAGON_URL не задан")
	}
	if strings.TrimSpace(req.PipelineID) == "" {
		return Result{}, fmt.Errorf("DRAGON_PIPELINE_ID не задан")
	}
	if len(req.Artifact.Payload) == 0 {
		return Result{}, fmt.Errorf("для Dragon обязательны байты архива")
	}
	expectedSHA := normalizeSHA256(req.Artifact.SHA256)
	actualSum := sha256.Sum256(req.Artifact.Payload)
	actualSHA := hex.EncodeToString(actualSum[:])
	if expectedSHA == "" {
		return Result{}, fmt.Errorf("для Dragon обязателен SHA-256 артефакта")
	}
	if expectedSHA != actualSHA {
		return Result{}, fmt.Errorf("SHA-256 артефакта перед отправкой не совпал: в БД %s, фактически %s", expectedSHA, actualSHA)
	}

	waitCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	created, err := c.createArchiveRun(waitCtx, req)
	if err != nil {
		return Result{}, err
	}
	baseResult := Result{
		RunID: created.ID, Status: "submitted", RunURL: created.RunURL,
		StatusURL: created.StatusURL, ArchiveSHA256: normalizeSHA256(created.SHA256),
		ArchiveFormat: created.Format, ArchiveFiles: created.Files,
		ArchiveBytes: created.Bytes, ArchiveSkipped: created.Skipped,
	}
	receivedSHA := normalizeSHA256(created.SHA256)
	if receivedSHA == "" {
		return baseResult, fmt.Errorf("Dragon не вернул SHA-256 принятого архива")
	}
	if receivedSHA != actualSHA {
		return baseResult, fmt.Errorf("Dragon принял другие байты: отправлен SHA-256 %s, Dragon вернул %s", actualSHA, receivedSHA)
	}
	baseResult.ArtifactVerified = true
	if created.ID == "" {
		return baseResult, fmt.Errorf("Dragon не вернул id сканирования")
	}

	statusURL, err := c.safeDragonURL(created.StatusURL)
	if err != nil {
		return baseResult, fmt.Errorf("небезопасный status_url Dragon: %w", err)
	}
	if statusURL == "" {
		statusURL = c.baseURL + "/api/runs/" + url.PathEscape(created.ID) + "/status"
	}
	runURL, err := c.safeDragonURL(created.RunURL)
	if err != nil {
		return baseResult, fmt.Errorf("небезопасный run_url Dragon: %w", err)
	}
	if runURL == "" {
		runURL = c.baseURL + "/#/run/" + url.PathEscape(created.ID)
	}

	baseResult.StatusURL = statusURL
	baseResult.RunURL = runURL
	for {
		var status statusResponse
		if err := c.doJSON(waitCtx, http.MethodGet, statusURL, nil, &status); err != nil {
			return baseResult, fmt.Errorf("получение результата Dragon %s: %w", created.ID, err)
		}
		result := normalizeStatus(baseResult, status)
		if result.Done {
			return result, nil
		}

		timer := time.NewTimer(c.pollInterval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return baseResult, fmt.Errorf("ожидание Dragon %s: %w", created.ID, waitCtx.Err())
		case <-timer.C:
		}
	}
}

func (c *Client) createArchiveRun(ctx context.Context, req Request) (createResponse, error) {
	endpoint, err := url.Parse(c.baseURL + "/api/runs/archive")
	if err != nil {
		return createResponse{}, err
	}
	query := endpoint.Query()
	query.Set("pipeline_id", req.PipelineID)
	if strings.TrimSpace(req.RepositoryID) != "" {
		query.Set("repository_id", req.RepositoryID)
	}
	endpoint.RawQuery = query.Encode()

	reader, contentType, writerErr := archiveMultipart(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), reader)
	if err != nil {
		return createResponse{}, err
	}
	httpReq.Header.Set("Content-Type", contentType)
	c.authorize(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return createResponse{}, fmt.Errorf("создание архивного сканирования Dragon: %w", err)
	}
	defer resp.Body.Close()
	if err := <-writerErr; err != nil {
		return createResponse{}, fmt.Errorf("формирование multipart-запроса Dragon: %w", err)
	}
	if resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return createResponse{}, fmt.Errorf("создание архивного сканирования Dragon: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	var created createResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return createResponse{}, fmt.Errorf("неверный JSON создания Dragon: %w", err)
	}
	return created, nil
}

func archiveMultipart(req Request) (io.Reader, string, <-chan error) {
	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)
	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		fail := func(err error) {
			_ = writer.CloseWithError(err)
			errCh <- err
		}
		filename := filepath.Base(strings.TrimSpace(req.Artifact.Filename))
		if filename == "." || filename == "" {
			filename = "artifact.zip"
		}
		header := make(textproto.MIMEHeader)
		header.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{
			"name": "file", "filename": filename,
		}))
		header.Set("Content-Type", "application/x-zip-compressed")
		part, err := multipartWriter.CreatePart(header)
		if err != nil {
			fail(err)
			return
		}
		if _, err := io.Copy(part, bytes.NewReader(req.Artifact.Payload)); err != nil {
			fail(err)
			return
		}
		fields := map[string]string{
			"label":    req.Artifact.Version,
			"name":     req.Artifact.Name,
			"publish":  strconv.FormatBool(req.Publish),
			"priority": strconv.Itoa(req.Priority),
		}
		variables, err := json.Marshal(map[string]string{
			"MODERATION_EXTERNAL_ID":           req.ExternalID,
			"MODERATION_MANAGER":               req.Artifact.Manager,
			"MODERATION_PACKAGE":               req.Artifact.Name,
			"MODERATION_VERSION":               req.Artifact.Version,
			"MODERATION_SHA256":                normalizeSHA256(req.Artifact.SHA256),
			"SEC_AIE_PROJECT_LANGUAGE_GROUPS": "none",
		})
		if err != nil {
			fail(err)
			return
		}
		fields["variables"] = string(variables)
		for _, field := range []string{"label", "name", "publish", "priority", "variables"} {
			if err := multipartWriter.WriteField(field, fields[field]); err != nil {
				fail(err)
				return
			}
		}
		if err := multipartWriter.Close(); err != nil {
			fail(err)
			return
		}
		errCh <- writer.Close()
	}()
	return reader, multipartWriter.FormDataContentType(), errCh
}

func normalizeStatus(base Result, status statusResponse) Result {
	result := base
	if status.ID != "" {
		result.RunID = status.ID
	}
	result.Status = status.Status
	result.Done = terminalStatus(status.Status)
	result.Success = successfulStatus(status.Status)
	result.Pipeline = status.Pipeline
	result.Repo = status.Repo
	result.RepositoryID = status.RepositoryID
	result.Branch = status.Branch
	result.SHA = status.SHA
	result.Author = status.Author
	result.Message = status.Message
	result.Error = status.Error
	result.Event = status.Event
	result.Source = status.Source
	result.Archive = status.Archive
	result.Name = status.Name
	result.StartedBy = status.StartedBy
	result.Published = status.Published
	result.Publish = status.Publish
	result.Priority = status.Priority
	result.Stages = status.Stages
	result.Jobs = status.Jobs
	result.Variables = status.Variables
	result.OakshieldURL = status.OakshieldURL
	result.Findings = summarizeFindings(status.Jobs)
	return result
}

var (
	vulnerabilityCountRE = regexp.MustCompile(`(?i)\bvulnerabilit(?:y|ies)(?:\s+found)?\s*[:=]\s*(\d+)`)
	trivyTotalRE         = regexp.MustCompile(`(?i)\btotal\s*:\s*(\d+)`)
	secretCountRE        = regexp.MustCompile(`(?i)\bleaks?\s+found\s*:\s*(\d+)`)
	codeFindingsRE       = regexp.MustCompile(`(?i)\bfindings?\s*:\s*(\d+)`)
	codeFindingsTailRE   = regexp.MustCompile(`(?i)\b(\d+)\s+findings?\b`)
)

func summarizeFindings(jobs []Job) FindingSummary {
	var summary FindingSummary
	for _, job := range jobs {
		texts := make([]string, 0, len(job.Log))
		for _, line := range job.Log {
			texts = append(texts, line.Text)
		}
		scanner := strings.ToLower(strings.TrimSpace(job.Scanner))
		switch scanner {
		case "gitleaks":
			summary.Secrets += maxLogCount(texts, secretCountRE)
		case "semgrep", "gosec":
			summary.CodeFindings += maxLogCount(texts, codeFindingsRE, codeFindingsTailRE)
		case "trivy":
			count := maxLogCount(texts, vulnerabilityCountRE)
			if count == 0 {
				count = maxLogCount(texts, trivyTotalRE)
			}
			summary.Vulnerabilities += count
		default:
			summary.Vulnerabilities += maxLogCount(texts, vulnerabilityCountRE)
		}
	}
	summary.Total = summary.Vulnerabilities + summary.Secrets + summary.CodeFindings
	return summary
}

func maxLogCount(lines []string, patterns ...*regexp.Regexp) int {
	max := 0
	for _, line := range lines {
		for _, pattern := range patterns {
			match := pattern.FindStringSubmatch(line)
			if len(match) != 2 {
				continue
			}
			count, err := strconv.Atoi(match[1])
			if err == nil && count > max {
				max = count
			}
		}
	}
	return max
}

func terminalStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "success", "succeeded", "completed", "passed", "failed", "error", "cancelled", "canceled":
		return true
	default:
		return false
	}
}

func successfulStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "success", "succeeded", "completed", "passed":
		return true
	default:
		return false
	}
}

func normalizeSHA256(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "sha256:")))
}

func (c *Client) safeDragonURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	base, err := url.Parse(c.baseURL + "/")
	if err != nil {
		return "", err
	}
	reference, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	resolved := base.ResolveReference(reference)
	if !strings.EqualFold(resolved.Scheme, base.Scheme) || !strings.EqualFold(resolved.Host, base.Host) {
		return "", fmt.Errorf("адрес %q ведёт за пределы DRAGON_URL", raw)
	}
	return resolved.String(), nil
}

func (c *Client) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, body []byte, dst any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	if dst == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("неверный JSON: %w", err)
	}
	return nil
}
