package api

import (
	"testing"

	"moderation/internal/config"
)

func TestReplaceIssuerPrefix(t *testing.T) {
	tests := []struct {
		name, endpoint, from, to, want string
	}{
		{
			name:     "keycloak endpoint",
			endpoint: "http://keycloak:8080/realms/moderation/protocol/openid-connect/auth",
			from:     "http://keycloak:8080/realms/moderation",
			to:       "https://moderation.example/realms/moderation",
			want:     "https://moderation.example/realms/moderation/protocol/openid-connect/auth",
		},
		{
			name:     "unrelated endpoint is unchanged",
			endpoint: "https://idp.example/authorize",
			from:     "http://keycloak:8080/realms/moderation",
			to:       "https://moderation.example/realms/moderation",
			want:     "https://idp.example/authorize",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := replaceIssuerPrefix(test.endpoint, test.from, test.to); got != test.want {
				t.Fatalf("replaceIssuerPrefix() = %q, ожидалось %q", got, test.want)
			}
		})
	}
}

func TestOIDCJWKSIssuerUsesLegacyInternalAddressOnlyForSeededPublicIssuer(t *testing.T) {
	cfg := &config.Config{
		OIDCIssuer:       "http://keycloak:8080/realms/moderation",
		OIDCPublicIssuer: "https://moderation.example/realms/moderation",
	}
	if got := oidcJWKSIssuer(cfg, cfg.OIDCPublicIssuer); got != cfg.OIDCIssuer {
		t.Fatalf("legacy split issuer: %q", got)
	}
	changed := "https://company-sso.example/realms/main"
	if got := oidcJWKSIssuer(cfg, changed); got != changed {
		t.Fatalf("issuer из web не должен подменяться старым env: %q", got)
	}
}
