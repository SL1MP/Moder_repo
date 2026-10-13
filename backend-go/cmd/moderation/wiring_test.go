package main

import (
	"testing"
	"time"
)

func TestHTTPClientTimeouts(t *testing.T) {
	if got := newHTTPClient().Timeout; got != 60*time.Second {
		t.Fatalf("таймаут служебного HTTP-клиента = %s", got)
	}
	if got := newArtifactHTTPClient().Timeout; got != 30*time.Minute {
		t.Fatalf("таймаут клиента артефактори = %s, большие архивы будут обрываться", got)
	}
}
