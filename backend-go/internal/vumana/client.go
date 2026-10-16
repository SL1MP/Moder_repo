// Package vumana uploads CycloneDX documents to the corporate VuMana API.
//
// The HTTP contract intentionally mirrors sbom-utils/upload_sbom.py used by
// the existing GitLab pipeline: POST {VUMANA_API_URL}/sbom/upload as
// multipart/form-data with one field named "file" containing the SBOM JSON.
package vumana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

type Result struct {
	ID         string         `json:"id,omitempty"`
	URL        string         `json:"url,omitempty"`
	BrowserURL string         `json:"browser_url,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

type Uploader interface {
	Available() bool
	Upload(ctx context.Context, filename string, document []byte) (Result, error)
}

type Config struct {
	APIURL     string
	PublicURL  string
	Token      string
	Timeout    time.Duration
	HTTPClient *http.Client
}

type Client struct {
	apiURL    string
	publicURL string
	token     string
	timeout   time.Duration
	http      *http.Client
}

func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{
		apiURL: strings.TrimRight(strings.TrimSpace(cfg.APIURL), "/"),
		publicURL: strings.TrimRight(strings.TrimSpace(cfg.PublicURL), "/"),
		token: strings.TrimSpace(cfg.Token), timeout: timeout, http: httpClient,
	}
}

func (c *Client) Available() bool { return c != nil && c.apiURL != "" }

func (c *Client) Upload(ctx context.Context, filename string, document []byte) (Result, error) {
	if !c.Available() {
		return Result{}, fmt.Errorf("VUMANA_API_URL не задан")
	}
	if len(document) == 0 {
		return Result{}, fmt.Errorf("SBOM %s пуст", filename)
	}
	var parsed any
	if err := json.Unmarshal(document, &parsed); err != nil {
		return Result{}, fmt.Errorf("SBOM %s не является JSON: %w", filename, err)
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	name := filepath.Base(strings.TrimSpace(filename))
	if name == "" || name == "." {
		name = "sbom.cdx.json"
	}
	part, err := w.CreateFormFile("file", name)
	if err != nil {
		return Result{}, err
	}
	if _, err := part.Write(document); err != nil {
		return Result{}, err
	}
	if err := w.Close(); err != nil {
		return Result{}, err
	}

	uploadCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(uploadCtx, http.MethodPost,
		c.apiURL+"/sbom/upload", &body)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("загрузка SBOM в VuMana: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Result{}, fmt.Errorf("VuMana отклонила SBOM: HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Result{}, fmt.Errorf("ответ VuMana не разобран: %w", err)
	}
	result := Result{Raw: raw}
	result.ID, _ = raw["id"].(string)
	result.URL, _ = raw["url"].(string)
	result.BrowserURL = c.browserURL(result.URL)
	return result, nil
}

func (c *Client) browserURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.IsAbs() {
		return raw
	}
	if c.publicURL == "" {
		return raw
	}
	return c.publicURL + "/#" + raw
}
