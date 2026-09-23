package registry

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Downloader — менеджер, который забирает артефакт сам, а не одним GET по
// адресу из метаданных.
//
// Существует потому, что «артефакт» не у всех менеджеров является файлом,
// лежащим по ссылке. У docker это набор блобов, который надо собрать в архив
// по манифесту; у git — состояние репозитория на коммите, которого как файла
// вообще нет, пока его не создали. Заставлять DownloadStep знать об этом
// нельзя: он тогда превращается в набор веток на каждый менеджер.
//
// Плагин, не реализующий Downloader, скачивается обычным путём: Metadata даёт
// ArtifactURL, шаг делает GET. Так работают все менеджеры, у которых артефакт
// — файл (pypi, npm, maven, nuget, php, luarocks, terraform, conan, files).
type Downloader interface {
	// Download возвращает байты артефакта и имя файла под ним.
	//
	// limit — предел размера; превышение обязано быть ошибкой, а не обрезанным
	// файлом: усечённый архив распакуется наполовину и будет просканирован
	// наполовину, а выглядеть это будет как «проверено».
	Download(ctx context.Context, ref Ref, limit int64) (payload []byte, filename string, err error)
}

// --------------------------------------------------------------------------- вспомогательное

// tarGzDir упаковывает каталог в tar.gz — общий финал для менеджеров, у
// которых артефакт получается в виде дерева файлов (git, docker).
//
// Порядок файлов в архиве отсортирован: иначе два прогона по одному и тому же
// содержимому давали бы разные байты и разный sha256, и сверять артефакт было
// бы не с чем.
func tarGzDir(root string, limit int64) ([]byte, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Символические ссылки в архив не кладём: содержимое по ним не наше, а
		// ссылка, указывающая наружу дерева, — известный способ протащить
		// чужой файл в архив.
		if !d.Type().IsRegular() {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("обход каталога %s: %w", root, err)
	}
	sort.Strings(paths)

	var buf limitedBuffer
	buf.limit = limit
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		header := &tar.Header{
			Name:     filepath.ToSlash(rel),
			Mode:     int64(info.Mode().Perm()),
			Size:     info.Size(),
			Typeflag: tar.TypeReg,
			// Время намеренно нулевое: иначе sha256 архива зависел бы от
			// момента упаковки, а не от содержимого.
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(tw, file)
		file.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.data, buf.err
}

// limitedBuffer — буфер с потолком. Ошибка запоминается и возвращается в
// конце: обрывать запись посреди gzip-потока нельзя, а молча отдать усечённый
// архив — тем более.
type limitedBuffer struct {
	data  []byte
	limit int64
	err   error
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.err != nil {
		// Пишем дальше в никуда: gzip.Writer обязан закрыться без ошибки, а
		// результат всё равно не будет использован.
		return len(p), nil
	}
	if b.limit > 0 && int64(len(b.data)+len(p)) > b.limit {
		b.err = fmt.Errorf("артефакт больше допустимого предела (%d байт)", b.limit)
		b.data = nil
		return len(p), nil
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// safeFilename делает из произвольной строки имя файла, пригодное для пути в
// хранилище: без разделителей каталогов и без «..».
func safeFilename(value string) string {
	value = strings.TrimSpace(value)
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "..", "-", " ", "_")
	value = replacer.Replace(value)
	value = strings.Trim(value, ".-")
	if value == "" {
		return "artifact"
	}
	if len(value) > 200 {
		value = value[:200]
	}
	return value
}
