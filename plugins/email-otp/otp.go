package emailotp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// DefaultOTPLength defines the default number of digits for an OTP.
	DefaultOTPLength = 6

	// MinOTPLength is the minimum acceptable OTP length.
	MinOTPLength = 4

	// MaxOTPLength is the maximum acceptable OTP length.
	MaxOTPLength = 12

	// SaltBytes is the entropy size for per-OTP cryptographic salts.
	SaltBytes = 16
)

// GenerateCode generates a cryptographically secure numeric OTP of the specified length.
// It avoids modulo bias by rejecting bytes outside the largest uniform multiple of 10.
func GenerateCode(length int) (string, error) {
	if length < MinOTPLength || length > MaxOTPLength {
		return "", fmt.Errorf("email-otp: invalid OTP length %d (must be between %d and %d)", length, MinOTPLength, MaxOTPLength)
	}

	const digits = "0123456789"
	result := make([]byte, length)
	buf := make([]byte, 1)

	for i := 0; i < length; i++ {
		for {
			if _, err := rand.Read(buf); err != nil {
				return "", fmt.Errorf("email-otp: crypto/rand read error: %w", err)
			}
			// 250 is the largest multiple of 10 below 256. Discarding 250-255 eliminates modulo bias.
			if buf[0] < 250 {
				result[i] = digits[buf[0]%10]
				break
			}
		}
	}

	return string(result), nil
}

// GenerateSalt produces a random URL-safe hex salt to protect against rainbow table attacks.
func GenerateSalt() (string, error) {
	b := make([]byte, SaltBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("email-otp: salt generation error: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashOTP computes a salted SHA-256 hash of the OTP value.
// Plaintext codes are never stored in the database.
func HashOTP(code, salt string) string {
	payload := salt + ":" + code
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// CompareOTP compares the candidate code against the stored hash in constant time.
func CompareOTP(candidateCode, storedHash, salt string) bool {
	candidateHash := HashOTP(candidateCode, salt)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1
}

// GenerateID produces a random hex identifier for entity IDs.
func GenerateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("email-otp: failed to generate id")
	}
	return hex.EncodeToString(b), nil
}
