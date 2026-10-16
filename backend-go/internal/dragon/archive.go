package dragon

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
)

// PrepareArchive gives Dragon the ZIP expected by /api/runs/archive. ZIP
// packages (including wheels, nupkg and jars) are sent unchanged. Tarballs
// are expanded to ZIP so scanners see their files; opaque artifacts become
// one-file ZIPs. The original staging digest remains untouched.
func PrepareArchive(payload []byte, filename string, maxUnpacked int64) (Artifact, error) {
	if maxUnpacked <= 0 {
		maxUnpacked = 512 << 20
	}
	archive := payload
	archiveName := path.Base(filename)
	if len(payload) >= 4 && bytes.Equal(payload[:4], []byte("PK\x03\x04")) {
		zr, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
		if err != nil {
			return Artifact{}, fmt.Errorf("архив ZIP повреждён: %w", err)
		}
		var total uint64
		if len(zr.File) > 20000 {
			return Artifact{}, fmt.Errorf("ZIP превышает лимит файлов Dragon")
		}
		for _, file := range zr.File {
			name := path.Clean(file.Name)
			if name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
				return Artifact{}, fmt.Errorf("недопустимый путь внутри ZIP: %q", file.Name)
			}
			if file.UncompressedSize64 > uint64(maxUnpacked)-total {
				return Artifact{}, fmt.Errorf("ZIP превышает лимит распаковки Dragon")
			}
			total += file.UncompressedSize64
		}
		if !strings.EqualFold(path.Ext(archiveName), ".zip") {
			archiveName = strings.TrimSuffix(archiveName, path.Ext(archiveName)) + ".zip"
		}
	} else {
		var buf bytes.Buffer
		writer := zip.NewWriter(&buf)
		var err error
		switch {
		case len(payload) >= 2 && payload[0] == 0x1f && payload[1] == 0x8b:
			var gz *gzip.Reader
			gz, err = gzip.NewReader(bytes.NewReader(payload))
			if err == nil {
				err = copyTarToZip(writer, gz, maxUnpacked)
				_ = gz.Close()
			}
		case strings.HasSuffix(strings.ToLower(filename), ".tar"):
			err = copyTarToZip(writer, bytes.NewReader(payload), maxUnpacked)
		default:
			if int64(len(payload)) > maxUnpacked {
				err = fmt.Errorf("артефакт превышает лимит распаковки Dragon")
			} else {
				entry := path.Base(filename)
				if entry == "." || entry == "/" || entry == "" {
					entry = "package.bin"
				}
				var dst io.Writer
				dst, err = writer.Create(entry)
				if err == nil {
					_, err = dst.Write(payload)
				}
			}
		}
		closeErr := writer.Close()
		if err != nil {
			return Artifact{}, err
		}
		if closeErr != nil {
			return Artifact{}, closeErr
		}
		archive = buf.Bytes()
		if strings.HasSuffix(strings.ToLower(archiveName), ".tar.gz") {
			archiveName = archiveName[:len(archiveName)-len(".tar.gz")] + ".zip"
		} else {
			archiveName = strings.TrimSuffix(archiveName, path.Ext(archiveName)) + ".zip"
		}
	}
	sum := sha256.Sum256(archive)
	return Artifact{
		Filename: archiveName, SHA256: hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(archive)), Payload: archive,
	}, nil
}

func copyTarToZip(writer *zip.Writer, src io.Reader, limit int64) error {
	reader := tar.NewReader(src)
	var total int64
	files := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("распаковка tar: %w", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		name := path.Clean(header.Name)
		if name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") || header.Size < 0 {
			return fmt.Errorf("недопустимый путь внутри tar: %q", header.Name)
		}
		files++
		if files > 20000 || header.Size > limit-total {
			return fmt.Errorf("tar превышает лимит распаковки Dragon")
		}
		total += header.Size
		dst, err := writer.Create(name)
		if err != nil {
			return err
		}
		if _, err := io.CopyN(dst, reader, header.Size); err != nil {
			return err
		}
	}
}
