package organizations

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// GenerateID produces a cryptographically random, prefixed unique identifier.
func GenerateID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b[:]))
}

// GenerateToken generates a cryptographically secure 32-byte random hex token.
func GenerateToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("organizations: failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// HashToken computes the SHA-256 hex digest of a raw token string.
func HashToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// ConstantTimeCompare verifies whether two token hashes match without timing leakage.
func ConstantTimeCompare(expectedHash, actualHash string) bool {
	return subtle.ConstantTimeCompare([]byte(expectedHash), []byte(actualHash)) == 1
}
