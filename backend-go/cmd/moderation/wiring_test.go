package main

import (
	"testing"
	"time"
)

func TestHTTPClientTimeouts(t *testing.T) {
	if got := newHTTPClient().Timeout; got != 60*time.Second {
		t.Fatalf("таймаут служебного HTTP-клиента = %s", got)
	}
	if got := newRegistryHTTPClient(20 * time.Minute).Timeout; got != 20*time.Minute {
		t.Fatalf("таймаут клиента реестров = %s, большие Docker layers будут обрываться", got)
	}
	if got := newRegistryHTTPClient(0).Timeout; got != 20*time.Minute {
		t.Fatalf("таймаут клиента реестров по умолчанию = %s", got)
	}
	if got := newArtifactHTTPClient().Timeout; got != 30*time.Minute {
		t.Fatalf("таймаут клиента артефактори = %s, большие архивы будут обрываться", got)
	}
}
