package ott

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// ToOTTIdentifier formats a stored token value into a namespace lookup key ("one-time-token:<token>").
func ToOTTIdentifier(storedToken string) string {
	return "one-time-token:" + storedToken
}

// DefaultTokenHasher computes a SHA-256 hash of the input token encoded in unpadded Base64Url string format.
func DefaultTokenHasher(token string) (string, error) {
	if token == "" {
		return "", ErrInvalidParameter
	}
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// DefaultGenerateToken generates a cryptographically secure random token string of the requested byte length.
func DefaultGenerateToken(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("ott: failed to generate secure random token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
