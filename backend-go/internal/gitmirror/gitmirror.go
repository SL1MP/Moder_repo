// Package gitmirror запускает штатные скрипты зеркалирования Git-репозитория
// и установки корпоративного CI-шаблона во внутреннем GitLab.
package gitmirror

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Result — результат зеркалирования всех веток, тегов и LFS-объектов.
type Result struct {
	SourceURL          string `json:"source_url"`
	TargetPath         string `json:"target_path"`
	ProjectID          int64  `json:"project_id"`
	ProjectURL         string `json:"project_url"`
	Created            bool   `json:"created"`
	Forced             bool   `json:"forced"`
	Maintainer         string `json:"maintainer"`
	MaintainerAssigned bool   `json:"maintainer_assigned"`
	DefaultBranch string `json:"default_branch"`
	PTBranch      string `json:"pt_branch"`
	Branches      int    `json:"branches"`
	Tags          int    `json:"tags"`
	LFSSupported  bool   `json:"lfs_supported"`
}

// TemplateResult — итог установки шаблона в защищённые pt/*-ветки.
type TemplateResult struct {
	TargetPath          string `json:"target_path"`
	ProjectURL          string `json:"project_url"`
	BranchesProcessed   int    `json:"branches_processed"`
	BranchesChanged     int    `json:"branches_changed"`
	PreviousCIPreserved int    `json:"previous_ci_preserved"`
	TemplateProject     string `json:"template_project"`
	TemplateRef         string `json:"template_ref"`
	TemplatePath        string `json:"template_path"`
}

// Service — контракт конвейера. Интерфейс позволяет проверять шаги без
// настоящего GitLab и не связывает pipeline с Python-процессом.
type Service interface {
	Mirror(ctx context.Context, sourceURL, maintainer string) (Result, error)
	InstallTemplate(ctx context.Context, sourceURL string) (TemplateResult, error)
}

type Config struct {
	Enabled         bool
	GitLabURL       string
	APIToken        string
	PushToken       string
	PushUsername    string
	TemplateToken   string
	TemplateProject string
	TemplateRef     string
	TemplatePath    string
	TemplateMarker  string
	BranchPrefix    string
	Force           bool
	PythonBinary    string
	ScriptDir       string
	CACerts         string
	Timeout         time.Duration
}

type Client struct{ cfg Config }

func New(cfg Config) *Client { return &Client{cfg: cfg} }

func (c *Client) Mirror(ctx context.Context, sourceURL, maintainer string) (Result, error) {
	var result Result
	if !c.cfg.Enabled {
		return result, errors.New("зеркалирование Git выключено (GIT_MIRROR_ENABLED=false)")
	}
	if err := c.run(ctx, "git_mirror.py", []string{sourceURL, maintainer}, &result); err != nil {
		return Result{}, fmt.Errorf("зеркалирование репозитория: %w", err)
	}
	return result, nil
}

func (c *Client) InstallTemplate(ctx context.Context, sourceURL string) (TemplateResult, error) {
	var result TemplateResult
	targetPath, err := TargetPath(sourceURL)
	if err != nil {
		return result, err
	}
	if err := c.run(ctx, "ciyaml.py", []string{targetPath}, &result); err != nil {
		return TemplateResult{}, fmt.Errorf("установка CI-шаблона: %w", err)
	}
	return result, nil
}

// TargetPath повторяет нейтральную раскладку скрипта:
// https://host/group/project.git -> host/group/project.
func TargetPath(source string) (string, error) {
	raw := strings.TrimRight(strings.TrimSpace(source), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("ожидается полный URL Git-репозитория http(s)://host/group/project")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("URL Git-репозитория не должен содержать учётные данные, query или fragment")
	}
	path := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	if len(strings.Split(path, "/")) < 2 {
		return "", fmt.Errorf("URL Git-репозитория должен содержать группу и проект")
	}
	return strings.ToLower(u.Hostname()) + "/" + path, nil
}

func (c *Client) run(ctx context.Context, script string, args []string, out any) error {
	if strings.TrimSpace(c.cfg.GitLabURL) == "" || strings.TrimSpace(c.cfg.APIToken) == "" ||
		strings.TrimSpace(c.cfg.PushToken) == "" {
		return errors.New("не заданы GIT_MIRROR_GITLAB_URL, GIT_MIRROR_API_TOKEN или GIT_MIRROR_PUSH_TOKEN")
	}
	if script == "ciyaml.py" && (strings.TrimSpace(c.cfg.TemplateProject) == "" ||
		strings.TrimSpace(c.cfg.TemplatePath) == "") {
		return errors.New("не заданы GIT_MIRROR_TEMPLATE_PROJECT или GIT_MIRROR_TEMPLATE_PATH")
	}

	timeout := c.cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	python := strings.TrimSpace(c.cfg.PythonBinary)
	if python == "" {
		python = "python3"
	}
	scriptDir := strings.TrimSpace(c.cfg.ScriptDir)
	if scriptDir == "" {
		scriptDir = "/opt/moderation/git-mirror"
	}
	cmd := exec.CommandContext(runCtx, python, append([]string{filepath.Join(scriptDir, script)}, args...)...)
	cmd.Env = append(os.Environ(), c.environment()...)

	bundle, cleanup, err := certificateBundle(c.cfg.CACerts)
	if err != nil {
		return err
	}
	defer cleanup()
	if bundle != "" {
		cmd.Env = append(cmd.Env,
			"REQUESTS_CA_BUNDLE="+bundle,
			"SSL_CERT_FILE="+bundle,
			"GIT_SSL_CAINFO="+bundle,
		)
	}

	combined, err := cmd.CombinedOutput()
	if err != nil {
		detail := c.sanitize(string(combined))
		if len(detail) > 3000 {
			detail = detail[len(detail)-3000:]
		}
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("операция не уложилась в %s: %s", timeout, strings.TrimSpace(detail))
		}
		return fmt.Errorf("%s завершился с ошибкой: %s", script, strings.TrimSpace(detail))
	}

	prefix := "MODERATION_RESULT="
	scanner := bufio.NewScanner(strings.NewReader(string(combined)))
	payload := ""
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), prefix) {
			payload = strings.TrimPrefix(scanner.Text(), prefix)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("чтение результата %s: %w", script, err)
	}
	if payload == "" {
		return fmt.Errorf("%s не вернул структурированный результат", script)
	}
	if err := json.Unmarshal([]byte(payload), out); err != nil {
		return fmt.Errorf("разбор результата %s: %w", script, err)
	}
	return nil
}

func (c *Client) environment() []string {
	templateToken := c.cfg.TemplateToken
	if strings.TrimSpace(templateToken) == "" {
		templateToken = c.cfg.APIToken
	}
	return []string{
		"GIT_MIRROR_GITLAB_URL=" + strings.TrimRight(c.cfg.GitLabURL, "/"),
		"GIT_MIRROR_API_TOKEN=" + c.cfg.APIToken,
		"GIT_MIRROR_PUSH_TOKEN=" + c.cfg.PushToken,
		"GIT_MIRROR_PUSH_USERNAME=" + valueOr(c.cfg.PushUsername, "git"),
		"GIT_MIRROR_TEMPLATE_TOKEN=" + templateToken,
		"GIT_MIRROR_TEMPLATE_PROJECT=" + c.cfg.TemplateProject,
		"GIT_MIRROR_TEMPLATE_REF=" + valueOr(c.cfg.TemplateRef, "main"),
		"GIT_MIRROR_TEMPLATE_PATH=" + c.cfg.TemplatePath,
		"GIT_MIRROR_TEMPLATE_MARKER=" + valueOr(c.cfg.TemplateMarker, "###security###"),
		"GIT_MIRROR_BRANCH_PREFIX=" + valueOr(c.cfg.BranchPrefix, "pt/"),
		fmt.Sprintf("GIT_MIRROR_FORCE=%t", c.cfg.Force),
	}
}

func (c *Client) sanitize(value string) string {
	for _, secret := range []string{c.cfg.APIToken, c.cfg.PushToken, c.cfg.TemplateToken} {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "***")
		}
	}
	return value
}

func certificateBundle(paths string) (string, func(), error) {
	paths = strings.TrimSpace(paths)
	if paths == "" {
		return "", func() {}, nil
	}
	var files []string
	// REQUESTS_CA_BUNDLE и GIT_SSL_CAINFO заменяют, а не дополняют системный
	// bundle. Поэтому сначала включаем публичные корни Debian, затем
	// корпоративные — иначе GitHub/GitLab.com перестанут открываться.
	if _, err := os.Stat("/etc/ssl/certs/ca-certificates.crt"); err == nil {
		files = append(files, "/etc/ssl/certs/ca-certificates.crt")
	}
	for _, candidate := range strings.FieldsFunc(paths, func(r rune) bool { return r == ',' || r == os.PathListSeparator }) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil {
			return "", func() {}, fmt.Errorf("корпоративный CA %s: %w", candidate, err)
		}
		if !info.IsDir() {
			files = append(files, candidate)
			continue
		}
		entries, err := os.ReadDir(candidate)
		if err != nil {
			return "", func() {}, err
		}
		for _, entry := range entries {
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if !entry.IsDir() && (ext == ".crt" || ext == ".cer" || ext == ".pem") {
				files = append(files, filepath.Join(candidate, entry.Name()))
			}
		}
	}
	file, err := os.CreateTemp("", "moderation-git-ca-*.pem")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	for _, name := range files {
		body, err := os.ReadFile(name)
		if err != nil {
			_ = file.Close()
			cleanup()
			return "", func() {}, err
		}
		if _, err := file.Write(append(body, '\n')); err != nil {
			_ = file.Close()
			cleanup()
			return "", func() {}, err
		}
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return file.Name(), cleanup, nil
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
