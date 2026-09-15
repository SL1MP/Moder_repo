// Package unpack — безопасная распаковка артефакта для сканирования содержимого.
//
// Порт backend/app/services/artifact_unpack.py. Пакет из реестра — это архив
// (wheel и nupkg суть zip, sdist и npm — tar.gz). Чтобы прогнать по нему YARA и
// SAST, содержимое надо разложить на диск. Архив приходит из внешнего мира и
// доверия не заслуживает, поэтому распаковка ограничена со всех сторон:
//
//   - путь каждого элемента проверяется на выход за пределы каталога (zip-slip);
//   - символические и жёсткие ссылки пропускаются целиком — внутри пакета они не
//     нужны, а увести за пределы каталога могут;
//   - суммарный распакованный объём, размер одного файла и число файлов
//     ограничены (архивная бомба);
//   - вложенные архивы раскрываются на ограниченную глубину.
//
// Пакет ничего не знает ни о конвейере, ни о сканерах: на вход — байты, на
// выход — временный каталог, который вызывающая сторона обязана удалить через
// Cleanup.
//
// Отличие от Python-версии: там определение формата отдано zipfile.is_zipfile /
// tarfile.is_tarfile, которые прозрачно понимают gzip и bzip2. В Go такого нет,
// поэтому формат определяется по сигнатуре (см. detect) — это заодно снимает
// зависимость от расширения файла, которое во внешнем архиве может врать.
package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Limits — границы распаковки. Значения по умолчанию рассчитаны на пакет, а не
// на образ (те же числа, что в Python-версии UnpackLimits).
type Limits struct {
	MaxTotalBytes int64
	MaxFileBytes  int64
	MaxFiles      int
	MaxDepth      int
}

// DefaultLimits — значения по умолчанию, 1:1 с Python UnpackLimits.
func DefaultLimits() Limits {
	return Limits{
		MaxTotalBytes: 512 * 1024 * 1024,
		MaxFileBytes:  64 * 1024 * 1024,
		MaxFiles:      20_000,
		MaxDepth:      2,
	}
}

// withDefaults заполняет нулевые поля значениями по умолчанию: вызывающий код
// обычно задаёт один-два лимита из конфигурации, а не всю структуру.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	return l
}

// Result — что получилось. Root — каталог с содержимым, его и передают сканеру;
// удаляется через Cleanup (удаляется родитель Root, там же лежит служебное).
type Result struct {
	Root          string
	Files         int
	TotalBytes    int64
	SkippedUnsafe int
	SkippedLarge  int
	Truncated     bool // упёрлись в лимит, разложено не всё
	Notes         []string

	tempDir string // корень временного каталога, удаляется целиком
}

// NESTED_SUFFIXES — расширения, которые раскрываются вложенно: пакет может
// везти в себе ещё один архив.
var nestedSuffixes = []string{".zip", ".whl", ".nupkg", ".jar", ".tar", ".tar.gz", ".tgz", ".tar.bz2"}

type budget struct {
	limits Limits
	result *Result
}

// allows — влезает ли ещё один файл размера size. Вызывается ДО записи, чтобы
// архивная бомба не успела занять диск.
func (b *budget) allows(size int64) bool {
	if size > b.limits.MaxFileBytes {
		b.result.SkippedLarge++
		return false
	}
	if b.result.Files >= b.limits.MaxFiles {
		b.result.Truncated = true
		return false
	}
	if b.result.TotalBytes+size > b.limits.MaxTotalBytes {
		b.result.Truncated = true
		return false
	}
	return true
}

func (b *budget) account(size int64) {
	b.result.Files++
	b.result.TotalBytes += size
}

// safeTarget — путь назначения, если он не выводит за пределы base.
// Возвращает ok=false для абсолютных путей, путей с ".." и всего, что после
// Join оказалось вне base.
func safeTarget(base, name string) (string, bool) {
	if name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return "", false
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == string(filepath.Separator) || filepath.IsAbs(clean) {
		return "", false
	}
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return "", false
		}
	}
	target := filepath.Join(base, clean)
	// Повторная проверка после Join: Clean выше уже снял "..", но проверка
	// относительного пути ловит и то, что могло проскочить (например, имя,
	// состоящее из одних разделителей).
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return target, true
}

// copyLimited копирует не более limit байт. Возвращает ошибку, если источник
// оказался длиннее заявленного в заголовке архива размера — заголовку архива,
// пришедшего извне, верить нельзя, это отдельный вектор архивной бомбы.
func copyLimited(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	written, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return written, err
	}
	if written > limit {
		return written, fmt.Errorf("файл длиннее заявленного в архиве размера (%d байт)", limit)
	}
	return written, nil
}

func writeFile(target string, src io.Reader, size int64) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := copyLimited(f, src, size); err != nil {
		return err
	}
	return nil
}

// --------------------------------------------------------------------------- форматы

type kind int

const (
	kindUnknown kind = iota
	kindZip
	kindTar
	kindTarGz
	kindTarBz2
)

// detect определяет формат по сигнатуре файла, не по расширению: имя внутри
// внешнего архива подделать проще, чем содержимое.
func detect(path string) kind {
	f, err := os.Open(path)
	if err != nil {
		return kindUnknown
	}
	defer f.Close()

	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("PK\x05\x06")):
		return kindZip
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return kindTarGz
	case bytes.HasPrefix(head, []byte("BZh")):
		return kindTarBz2
	}
	// tar: магия "ustar" по смещению 257 (POSIX и GNU-варианты).
	if len(head) >= 265 && bytes.HasPrefix(head[257:], []byte("ustar")) {
		return kindTar
	}
	return kindUnknown
}

func extractZip(path string, into string, b *budget) error {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer archive.Close()

	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		// Внутри zip ссылки представлены битом типа в режиме файла; как и в
		// tar, они не нужны и способны увести за пределы каталога.
		if entry.Mode()&os.ModeSymlink != 0 {
			b.result.SkippedUnsafe++
			continue
		}
		target, ok := safeTarget(into, entry.Name)
		if !ok {
			b.result.SkippedUnsafe++
			continue
		}
		size := int64(entry.UncompressedSize64)
		if !b.allows(size) {
			continue
		}
		src, err := entry.Open()
		if err != nil {
			b.result.Notes = append(b.result.Notes, fmt.Sprintf("элемент не прочитан (%s): %v", entry.Name, err))
			continue
		}
		err = writeFile(target, src, size)
		src.Close()
		if err != nil {
			b.result.Notes = append(b.result.Notes, fmt.Sprintf("элемент не распакован (%s): %v", entry.Name, err))
			continue
		}
		b.account(size)
	}
	return nil
}

func extractTar(path string, into string, b *budget, k kind) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var src io.Reader = f
	switch k {
	case kindTarGz:
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		src = gz
	case kindTarBz2:
		src = bzip2.NewReader(f)
	}

	archive := tar.NewReader(src)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Ссылки и спец-файлы не распаковываем вовсе: внутри пакета они не
		// нужны, а вывести за пределы каталога способны.
		if header.Typeflag != tar.TypeReg {
			if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
				b.result.SkippedUnsafe++
			}
			continue
		}
		target, ok := safeTarget(into, header.Name)
		if !ok {
			b.result.SkippedUnsafe++
			continue
		}
		if !b.allows(header.Size) {
			continue
		}
		if err := writeFile(target, archive, header.Size); err != nil {
			b.result.Notes = append(b.result.Notes, fmt.Sprintf("элемент не распакован (%s): %v", header.Name, err))
			continue
		}
		b.account(header.Size)
	}
}

// extractAny раскрывает архив известного вида. false — формат не распознан.
// Битый архив не считается ошибкой конвейера: пишем заметку и идём дальше,
// решение о пакете принимает шаг, а не распаковщик.
func extractAny(path string, into string, b *budget) bool {
	k := detect(path)
	if k == kindUnknown {
		return false
	}
	var err error
	if k == kindZip {
		err = extractZip(path, into, b)
	} else {
		err = extractTar(path, into, b, k)
	}
	if err != nil {
		b.result.Notes = append(b.result.Notes,
			fmt.Sprintf("архив не раскрыт (%s): %v", filepath.Base(path), err))
		return false
	}
	return true
}

func hasNestedSuffix(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range nestedSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// expandNested раскрывает вложенные архивы: пакет может везти в себе ещё один.
func expandNested(root string, b *budget, depth int) {
	if depth >= b.limits.MaxDepth {
		return
	}
	var candidates []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.Mode().IsRegular() {
			return nil //nolint:nilerr // недоступный элемент пропускается, а не роняет обход
		}
		if hasNestedSuffix(info.Name()) {
			candidates = append(candidates, path)
		}
		return nil
	})
	sort.Strings(candidates)

	for _, path := range candidates {
		into := path + "__unpacked"
		if err := os.MkdirAll(into, 0o755); err != nil {
			continue
		}
		if extractAny(path, into, b) {
			expandNested(into, b, depth+1)
		}
	}
}

// --------------------------------------------------------------------------- API

// Artifact раскладывает артефакт во временный каталог. Каталог удаляет
// вызывающий через Cleanup — в том числе при ошибке шага, поэтому Cleanup
// ставится в defer сразу после успешного вызова.
func Artifact(payload []byte, filename string, limits Limits) (*Result, error) {
	limits = limits.withDefaults()

	tempDir, err := os.MkdirTemp("", "moderation-scan-")
	if err != nil {
		return nil, fmt.Errorf("временный каталог для распаковки: %w", err)
	}
	result := &Result{tempDir: tempDir}
	b := &budget{limits: limits, result: result}

	archivePath := filepath.Join(tempDir, "__artifact__")
	if err := os.WriteFile(archivePath, payload, 0o600); err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("запись артефакта во временный файл: %w", err)
	}
	content := filepath.Join(tempDir, "content")
	if err := os.MkdirAll(content, 0o755); err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("создание каталога содержимого: %w", err)
	}

	if !extractAny(archivePath, content, b) {
		// Не архив (например, одиночный .py или .js) — сканируем как файл.
		name := filepath.Base(filepath.FromSlash(filename))
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "artifact"
		}
		target, ok := safeTarget(content, name)
		if !ok {
			target = filepath.Join(content, "artifact")
		}
		if err := os.WriteFile(target, payload, 0o644); err != nil {
			os.RemoveAll(tempDir)
			return nil, fmt.Errorf("запись артефакта для сканирования: %w", err)
		}
		b.account(int64(len(payload)))
		result.Notes = append(result.Notes, "артефакт не является архивом — просканирован как один файл")
	} else {
		expandNested(content, b, 0)
	}

	_ = os.Remove(archivePath)
	result.Root = content
	if result.Truncated {
		result.Notes = append(result.Notes, fmt.Sprintf(
			"распаковка ограничена: %d файлов, %d МБ — часть содержимого не проверена",
			result.Files, result.TotalBytes/(1024*1024)))
	}
	return result, nil
}

// Cleanup удаляет временный каталог распаковки. Безопасен для nil и для
// повторного вызова.
func Cleanup(r *Result) {
	if r == nil || r.tempDir == "" {
		return
	}
	_ = os.RemoveAll(r.tempDir)
	r.tempDir = ""
}
