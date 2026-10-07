package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

const APITokenPrefix = "dso_pat_"

func NewOpaqueToken(prefix string) (plain, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	plain = prefix + base64.RawURLEncoding.EncodeToString(raw)
	return plain, HashToken(plain), nil
}

func HashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
