package apikeys

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	// DefaultKeyPrefix is the default prefix prepended to issued API keys.
	DefaultKeyPrefix = "gma_"

	// EntropyBytes is the number of cryptographically secure random bytes generated for each key (256 bits).
	EntropyBytes = 32

	// PublicPrefixLength defines how many characters from the start of rawKey are retained for human display.
	PublicPrefixLength = 12
)

// GenerateID produces a random hexadecimal identifier with an optional prefix (e.g. "ak_...").
func GenerateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// GenerateRawKey produces a new cryptographically secure random API key, its public prefix,
// and its SHA-256 hash representation. The raw key must be returned to the caller immediately
// and NEVER stored in persistence.
func GenerateRawKey(prefix string) (rawKey string, publicPrefix string, keyHash string, err error) {
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}

	buf := make([]byte, EntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("apikeys: crypto/rand entropy source failed: %w", err)
	}

	secret := base64.RawURLEncoding.EncodeToString(buf)
	rawKey = prefix + secret

	if len(rawKey) >= PublicPrefixLength {
		publicPrefix = rawKey[:PublicPrefixLength]
	} else {
		publicPrefix = rawKey
	}

	keyHash = HashKey(rawKey)
	return rawKey, publicPrefix, keyHash, nil
}

// HashKey computes the SHA-256 hex digest of a raw API key token.
func HashKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

// VerifyKey performs a constant-time comparison between a candidate raw key's SHA-256 hash
// and the stored expected hash.
func VerifyKey(rawKey string, expectedHash string) bool {
	candidateHash := HashKey(rawKey)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(expectedHash)) == 1
}

// ConstantTimeEqual performs constant-time comparison between two string values.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// DummyHashVerification simulates key verification timing against a fixed dummy hash
// to equalize response timing when a requested key does not exist.
func DummyHashVerification(rawKey string) bool {
	dummyExpected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	return VerifyKey(rawKey, dummyExpected)
}
