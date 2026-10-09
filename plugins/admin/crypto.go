package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// generateSecureToken creates a cryptographically secure 256-bit random token
// and its corresponding SHA-256 hash hex string.
func generateSecureToken() (raw string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(h[:])
	return raw, hash, nil
}
