package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

type largeBlobDoer struct{ body []byte }

func (d largeBlobDoer) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(d.body)),
	}, nil
}

// Регрессия postgres:14.23: прежний общий лимит ответа реестра (64 MiB)
// обрезал крупный layer и выдавал ложное несовпадение digest.
func TestDockerBlobMayExceedMetadataResponseLimit(t *testing.T) {
	body := bytes.Repeat([]byte{0x5a}, maxRegistryResponseBytes+1)
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	p := &Docker{BaseURL: "https://registry.test", HTTP: largeBlobDoer{body: body}}

	got, err := p.blob(context.Background(), "library/postgres", digest, int64(len(body)))
	if err != nil {
		t.Fatalf("blob крупнее 64 MiB был обрезан: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("получено %d байт вместо %d", len(got), len(body))
	}

	_, err = p.blob(context.Background(), "library/postgres", digest, 1024)
	if err == nil || !strings.Contains(err.Error(), "предел") {
		t.Fatalf("превышение настоящего лимита не названо: %v", err)
	}
}
