package deviceauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// userCodeCharset contains unambiguous uppercase characters (omits 0, O, 1, I).
const userCodeCharset = "BCDFGHJKLMNPQRSTVWXYZ23456789"

// generateDeviceCode creates a cryptographically secure 256-bit random device code
// and returns both the plaintext code and its SHA-256 hash hex string.
func generateDeviceCode() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	code := hex.EncodeToString(b)
	hash := hashDeviceCode(code)
	return code, hash, nil
}

// hashDeviceCode returns the SHA-256 hex string of a device code.
func hashDeviceCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// generateUserCode creates an 8-character human-friendly user code formatted as XXXX-XXXX.
func generateUserCode() (string, error) {
	indices := make([]byte, 8)
	if _, err := rand.Read(indices); err != nil {
		return "", err
	}

	charsetLen := byte(len(userCodeCharset))
	var sb strings.Builder
	for i, b := range indices {
		if i == 4 {
			sb.WriteByte('-')
		}
		sb.WriteByte(userCodeCharset[b%charsetLen])
	}
	return sb.String(), nil
}

// normalizeUserCode cleans user code by uppercasing and stripping whitespace and hyphens.
func normalizeUserCode(code string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(code))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	if len(cleaned) == 8 {
		return cleaned[:4] + "-" + cleaned[4:]
	}
	return cleaned
}

// generateID creates a unique random identifier for grants.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// generateSessionToken creates a random session token and its SHA-256 hash.
func generateSessionToken() (raw string, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	raw = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(h[:])
	return raw, hash
}
