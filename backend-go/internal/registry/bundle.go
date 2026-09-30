package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// BundleFile — один реальный файл релиза внутри транспортного архива.
// Транспорт нужен только между download и publish: в целевой репозиторий сам
// .tgz не попадает, каждый файл публикуется нативно для своего формата.
type BundleFile struct {
	Name string
	Data []byte
}

type bundleManifest struct {
	Format  int    `json:"format"`
	Manager string `json:"manager"`
}

const (
	bundleMarker   = ".moderation-bundle.json"
	bundleFormat   = 1
	maxBundleFiles = 512
)

// PackBundle собирает детерминированный tar.gz. Имена ограничены basename:
// upstream не может подсунуть путь за пределы каталога версии.
func PackBundle(manager string, files []BundleFile, limit int64) ([]byte, error) {
	if len(files) == 0 || len(files) > maxBundleFiles {
		return nil, fmt.Errorf("некорректное число файлов %s bundle: %d", manager, len(files))
	}
	seen := make(map[string]bool, len(files))
	total := int64(0)
	for i := range files {
		name := path.Clean(strings.TrimSpace(files[i].Name))
		if name == "" || name == "." || name == ".." || path.Base(name) != name || name == bundleMarker {
			return nil, fmt.Errorf("небезопасное имя файла в %s bundle: %q", manager, files[i].Name)
		}
		if seen[name] {
			return nil, fmt.Errorf("повторяющийся файл в %s bundle: %s", manager, name)
		}
		seen[name] = true
		files[i].Name = name
		total += int64(len(files[i].Data))
		if limit > 0 && total > limit {
			return nil, fmt.Errorf("файлы %s-релиза больше допустимого предела %d байт", manager, limit)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	manifest, _ := json.Marshal(bundleManifest{Format: bundleFormat, Manager: manager})
	var out limitedBuffer
	out.limit = limit
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write(bundleMarker, manifest); err != nil {
		return nil, err
	}
	for _, file := range files {
		if err := write(file.Name, file.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if out.err != nil {
		return nil, out.err
	}
	return out.data, nil
}

// UnpackBundle проверяет маркер, менеджер, пути и суммарный размер. Функция
// экспортирована для адаптеров Nexus/Artifactory, которые публикуют реальные
// файлы, а не транспортный архив.
func UnpackBundle(data []byte, expectedManager string, limit int64) ([]BundleFile, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s bundle не является gzip: %w", expectedManager, err)
	}
	defer gz.Close()
	t := tar.NewReader(gz)
	var manifest bundleManifest
	var files []BundleFile
	seen := map[string]bool{}
	total := int64(0)
	entries := 0
	for {
		header, nextErr := t.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, fmt.Errorf("%s bundle не разобран: %w", expectedManager, nextErr)
		}
		entries++
		// Один дополнительный entry — служебный manifest.
		if entries > maxBundleFiles+1 {
			return nil, fmt.Errorf("%s bundle содержит слишком много файлов", expectedManager)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(header.Name)
		if name != header.Name || path.Base(name) != name || name == "." || name == ".." || seen[name] {
			return nil, fmt.Errorf("небезопасное или повторяющееся имя в %s bundle: %q", expectedManager, header.Name)
		}
		seen[name] = true
		if header.Size < 0 || (limit > 0 && total+header.Size > limit) {
			return nil, fmt.Errorf("распакованный %s bundle больше допустимого предела", expectedManager)
		}
		body, readErr := io.ReadAll(io.LimitReader(t, header.Size+1))
		if readErr != nil || int64(len(body)) != header.Size {
			return nil, fmt.Errorf("файл %s из %s bundle прочитан не полностью", name, expectedManager)
		}
		total += header.Size
		if name == bundleMarker {
			if err := json.Unmarshal(body, &manifest); err != nil {
				return nil, fmt.Errorf("маркер %s bundle не разобран: %w", expectedManager, err)
			}
			continue
		}
		files = append(files, BundleFile{Name: name, Data: body})
	}
	if manifest.Format != bundleFormat || manifest.Manager != expectedManager {
		return nil, fmt.Errorf("ожидался transport bundle менеджера %s", expectedManager)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s bundle не содержит файлов релиза", expectedManager)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}
