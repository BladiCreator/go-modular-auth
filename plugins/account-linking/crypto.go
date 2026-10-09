package accountlinking

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// generateSecureToken creates a cryptographically secure random token with a given prefix.
func generateSecureToken(prefix string, byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: failed to read entropy: %w", err)
	}
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b)), nil
}

// hashToken computes a SHA-256 hexadecimal hash of the plain token for secure storage.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
