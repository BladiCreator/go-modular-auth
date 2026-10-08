package phone

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// DefaultOTPLength defines the default digit count for phone OTPs.
	DefaultOTPLength = 6

	// MinOTPLength defines the minimum acceptable OTP length.
	MinOTPLength = 4

	// MaxOTPLength defines the maximum acceptable OTP length.
	MaxOTPLength = 12

	// SaltBytes defines the random entropy size for per-OTP salts.
	SaltBytes = 16
)

// GenerateCode creates a cryptographically secure numeric OTP of the specified length.
// It eliminates modulo bias by discarding random bytes >= 250 (the largest multiple of 10 below 256).
func GenerateCode(length int) (string, error) {
	if length < MinOTPLength || length > MaxOTPLength {
		return "", fmt.Errorf("phone: invalid OTP length %d (must be between %d and %d)", length, MinOTPLength, MaxOTPLength)
	}

	const digits = "0123456789"
	result := make([]byte, length)
	buf := make([]byte, 1)

	for i := 0; i < length; i++ {
		for {
			if _, err := rand.Read(buf); err != nil {
				return "", fmt.Errorf("phone: crypto/rand read error: %w", err)
			}
			if buf[0] < 250 {
				result[i] = digits[buf[0]%10]
				break
			}
		}
	}

	return string(result), nil
}

// GenerateSalt produces a random hex-encoded salt string.
func GenerateSalt() (string, error) {
	b := make([]byte, SaltBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("phone: salt generation error: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateID produces a random hex-encoded unique identifier.
func GenerateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("phone: id generation error")
	}
	return hex.EncodeToString(b), nil
}

// HashOTP produces a salted SHA-256 hash string for the OTP code.
// Plaintext codes are never stored in persistence layer.
func HashOTP(code, salt string) string {
	payload := salt + ":" + code
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// CompareOTP verifies a candidate code against the stored hash in constant time.
func CompareOTP(candidateCode, storedHash, salt string) bool {
	candidateHash := HashOTP(candidateCode, salt)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1
}
