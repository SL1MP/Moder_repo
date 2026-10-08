// Package dragon integrates the moderation pipeline with Dragon artifact scans.
//
// Dragon executes scanners, but it does not decide whether a package may be
// published. It returns integrity evidence and a normalized finding summary;
// the moderation pipeline applies the policy and remains the only component
// that can allow publication.
package dragon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Artifact is the immutable object Dragon runners must scan.
type Artifact struct {
	Manager   string `json:"manager"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// Request starts (or finds by ExternalID) one artifact scan.
type Request struct {
	PipelineID string   `json:"pipeline_id"`
	ExternalID string   `json:"external_id"`
	Artifact   Artifact `json:"artifact"`
	Publish    bool     `json:"publish"`
}

// Summary is normalized evidence from all scanners. Scanner-specific reports
// remain in Dragon and can be opened through ReportURLs.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

func (s Summary) Total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Unknown
}

// Result is returned only after Dragon marks the run done.
type Result struct {
	RunID            string   `json:"id"`
	Status           string   `json:"status"`
	Done             bool     `json:"done"`
	Success          bool     `json:"success"`
	ArtifactVerified bool     `json:"artifact_verified"`
	EvidenceComplete bool     `json:"evidence_complete"`
	Summary          Summary  `json:"summary"`
	ReportURLs       []string `json:"report_urls"`
	RunURL           string   `json:"run_url"`
}

// Scanner is the pipeline-facing contract. Tests use a small fake; production
// uses Client below.
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
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		token: strings.TrimSpace(cfg.Token), pollInterval: poll,
		timeout: timeout, http: httpClient,
	}
}

type createResponse struct {
	ID string `json:"id"`
}

func (c *Client) Scan(ctx context.Context, req Request) (Result, error) {
	if c.baseURL == "" {
		return Result{}, fmt.Errorf("DRAGON_URL не задан")
	}
	if strings.TrimSpace(req.PipelineID) == "" {
		return Result{}, fmt.Errorf("DRAGON_PIPELINE_ID не задан")
	}
	if strings.TrimSpace(req.Artifact.SHA256) == "" || strings.TrimSpace(req.Artifact.URL) == "" {
		return Result{}, fmt.Errorf("для Dragon обязательны URL и SHA-256 артефакта")
	}

	raw, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	var created createResponse
	if err := c.doJSON(ctx, http.MethodPost, c.baseURL+"/api/artifact-runs", raw, &created); err != nil {
		return Result{}, fmt.Errorf("создание сканирования Dragon: %w", err)
	}
	if created.ID == "" {
		return Result{}, fmt.Errorf("Dragon не вернул id сканирования")
	}

	waitCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	for {
		var result Result
		statusURL := c.baseURL + "/api/runs/" + created.ID + "/status"
		if err := c.doJSON(waitCtx, http.MethodGet, statusURL, nil, &result); err != nil {
			return Result{}, fmt.Errorf("получение результата Dragon %s: %w", created.ID, err)
		}
		if result.RunID == "" {
			result.RunID = created.ID
		}
		if result.RunURL == "" {
			result.RunURL = c.baseURL + "/runs/" + created.ID
		}
		if result.Done {
			return result, nil
		}

		timer := time.NewTimer(c.pollInterval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return Result{}, fmt.Errorf("ожидание Dragon %s: %w", created.ID, waitCtx.Err())
		case <-timer.C:
		}
	}
}

func (c *Client) doJSON(ctx context.Context, method, url string, body []byte, dst any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
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

