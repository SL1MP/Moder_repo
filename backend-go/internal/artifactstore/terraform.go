package artifactstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"sync"

	"moderation/internal/registry"
)

var terraformMirrorPublishMu sync.Mutex

type terraformMirrorIndex struct {
	Versions map[string]json.RawMessage `json:"versions"`
}

type terraformMirrorVersion struct {
	Archives map[string]struct {
		URL    string   `json:"url"`
		Hashes []string `json:"hashes"`
	} `json:"archives"`
}

// publishTerraformBundle раскладывает проверенный релиз как статическое
// Terraform network mirror. terraform-internal должен быть raw hosted:
// Terraform CLI читает JSON и ZIP по точным путям, а не через компонентный
// API отдельного пакетного формата.
func publishTerraformBundle(ctx context.Context, store Store, t Target,
	files []registry.BundleFile) (string, error) {
	// index.json объединяет версии read-modify-write. Один worker обрабатывает
	// несколько заявок параллельно, поэтому без блокировки две публикации могли
	// потерять версии друг друга в индексе.
	terraformMirrorPublishMu.Lock()
	defer terraformMirrorPublishMu.Unlock()

	version := strings.TrimSpace(strings.SplitN(t.Version, ":", 2)[0])
	if version == "" || strings.Count(t.Name, "/") != 1 {
		return "", fmt.Errorf("некорректная Terraform-координата %q@%q", t.Name, t.Version)
	}
	byName := make(map[string][]byte, len(files))
	for _, file := range files {
		byName[file.Name] = file.Data
	}
	versionName := version + ".json"
	versionData, ok := byName[versionName]
	if !ok {
		return "", fmt.Errorf("Terraform bundle не содержит %s", versionName)
	}
	var descriptor terraformMirrorVersion
	if err := json.Unmarshal(versionData, &descriptor); err != nil || len(descriptor.Archives) == 0 {
		return "", fmt.Errorf("Terraform bundle содержит некорректный %s", versionName)
	}

	root := "registry.terraform.io/" + strings.Trim(t.Name, "/")
	// Сначала кладём архивы. JSON версии и index становятся видимыми только
	// после успешной публикации всех файлов, поэтому CLI не увидит полурелиз.
	for platform, archive := range descriptor.Archives {
		rel := path.Clean(strings.TrimSpace(archive.URL))
		wantPrefix := version + "/"
		if rel == "." || !strings.HasPrefix(rel, wantPrefix) || path.Base(rel) == "." ||
			strings.Contains(rel, "..") {
			return "", fmt.Errorf("небезопасный URL архива Terraform %s: %q", platform, archive.URL)
		}
		name := path.Base(rel)
		data, exists := byName[name]
		if !exists {
			return "", fmt.Errorf("Terraform bundle не содержит архив %s для %s", name, platform)
		}
		if err := writeImmutableRaw(ctx, store, t.Repo, root+"/"+rel, data,
			"application/zip"); err != nil {
			return "", err
		}
	}
	if err := writeImmutableRaw(ctx, store, t.Repo, root+"/"+versionName, versionData,
		"application/json"); err != nil {
		return "", err
	}

	indexPath := root + "/index.json"
	index := terraformMirrorIndex{Versions: map[string]json.RawMessage{}}
	if existing, err := store.ReadFile(ctx, t.Repo, indexPath); err == nil {
		if err := json.Unmarshal(existing, &index); err != nil {
			return "", fmt.Errorf("существующий Terraform index.json повреждён: %w", err)
		}
	} else if file, statErr := store.StatFile(ctx, t.Repo, indexPath); statErr != nil {
		return "", statErr
	} else if file != nil {
		return "", fmt.Errorf("существующий Terraform index.json не удалось прочитать: %w", err)
	}
	if index.Versions == nil {
		index.Versions = map[string]json.RawMessage{}
	}
	if _, exists := index.Versions[version]; !exists {
		index.Versions[version] = json.RawMessage(`{}`)
	}
	indexData, err := json.Marshal(index)
	if err != nil {
		return "", err
	}
	if err := store.WriteFile(ctx, t.Repo, indexPath, indexData, "application/json"); err != nil {
		return "", err
	}
	return rawFileURL(store, t.Repo, root+"/"+versionName), nil
}

func writeImmutableRaw(ctx context.Context, store Store, repo, filePath string,
	data []byte, contentType string) error {
	existing, err := store.ReadFile(ctx, repo, filePath)
	switch {
	case err == nil:
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("Terraform asset %s уже существует с другим содержимым", filePath)
		}
		return nil
	case err != nil:
		file, statErr := store.StatFile(ctx, repo, filePath)
		if statErr != nil {
			return statErr
		}
		if file != nil {
			return fmt.Errorf("Terraform asset %s существует, но не читается: %w", filePath, err)
		}
	}
	return store.WriteFile(ctx, repo, filePath, data, contentType)
}

func rawFileURL(store Store, repo, filePath string) string {
	switch concrete := store.(type) {
	case *Nexus:
		return concrete.fileURL(repo, filePath)
	case *Generic:
		return concrete.fileURL(repo, filePath)
	default:
		return store.ArtifactURL(Target{Repo: repo, Manager: "files", Path: filePath,
			Name: path.Dir(filePath), Filename: path.Base(filePath)})
	}
}
