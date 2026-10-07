package auth

import (
	"strings"
	"testing"
)

func TestNewAPITokenUsesOakshieldPrefixAndHash(t *testing.T) {
	plain, hash, err := NewOpaqueToken(APITokenPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, "dso_pat_") {
		t.Fatalf("prefix = %q", plain)
	}
	if len(plain) <= len(APITokenPrefix) {
		t.Fatal("токен не содержит случайную часть")
	}
	if hash != HashToken(plain) {
		t.Fatal("сохранённый хеш не соответствует открытому токену")
	}
	if strings.Contains(hash, plain) {
		t.Fatal("в базе нельзя сохранять открытый PAT")
	}
}

func TestOpaqueTokensAreUnique(t *testing.T) {
	first, _, err := NewOpaqueToken("")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := NewOpaqueToken("")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("два refresh token совпали")
	}
}
