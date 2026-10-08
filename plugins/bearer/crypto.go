package bearer

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// TokenEntropyBytes defines the amount of cryptographically secure random bytes
	// used for generating opaque bearer tokens (32 bytes = 256 bits of entropy).
	TokenEntropyBytes = 32

	// IDEntropyBytes defines the amount of random bytes used for generating entity IDs (16 bytes = 128 bits).
	IDEntropyBytes = 16
)

// GenerateID produces a random hex-encoded unique identifier for entity records.
func GenerateID() (string, error) {
	b := make([]byte, IDEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("bearer: failed to generate secure id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateToken generates an opaque, URL-safe random secret bearer token.
// If prefix is non-empty, it prepends the prefix to the token (e.g. "gmb_").
func GenerateToken(prefix string) (string, error) {
	b := make([]byte, TokenEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("bearer: failed to generate secure token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	if prefix != "" {
		return prefix + token, nil
	}
	return token, nil
}

// HashToken computes the SHA-256 digest of a bearer token and returns it as a lowercase hex string.
//
// Bearer tokens carry 256 bits of entropy, so a fast cryptographic hash is optimal:
// brute-force attacks against 256 bits are mathematically infeasible, while lookups in persistence
// and cache remain strictly O(1).
func HashToken(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeCompare compares two hash strings in constant time to prevent side-channel timing attacks.
func ConstantTimeCompare(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidateTokenFormat checks if a token string satisfies minimum sanity requirements (non-empty, sane length).
func ValidateTokenFormat(token string) error {
	if token == "" {
		return ErrInvalidToken
	}
	if len(token) < 16 || len(token) > 512 {
		return errors.New("bearer: token length out of acceptable bounds")
	}
	return nil
}
