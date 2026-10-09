package oauthprovider

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// generateRandomToken generates a cryptographically secure random string.
func generateRandomToken(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth_provider: crypto/rand read error: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashToken computes a SHA-256 hash representation of an opaque token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// hashClientSecret generates a salted SHA-256 hash for storing client secrets safely.
func hashClientSecret(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(secret))
	digest := h.Sum(nil)
	return fmt.Sprintf("$s256$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(digest)), nil
}

// verifyClientSecret validates a plaintext secret against a salted hash in constant time.
func verifyClientSecret(hashed, secret string) bool {
	parts := strings.Split(hashed, "$")
	if len(parts) != 4 || parts[1] != "s256" {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expectedDigest, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(secret))
	digest := h.Sum(nil)

	return subtle.ConstantTimeCompare(expectedDigest, digest) == 1
}

// verifyPKCE verifies a code_verifier against a code_challenge per RFC 7636.
func verifyPKCE(verifier, challenge, method string, allowPlain bool) error {
	if verifier == "" || challenge == "" {
		return ErrPKCERequired
	}
	// RFC 7636 specifies code_verifier length must be between 43 and 128 characters
	if len(verifier) < 43 || len(verifier) > 128 {
		return ErrInvalidPKCE
	}

	switch method {
	case CodeChallengeMethodS256:
		h := sha256.Sum256([]byte(verifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
		if subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(challenge)) != 1 {
			return ErrInvalidPKCE
		}
		return nil
	case CodeChallengeMethodPlain:
		if !allowPlain {
			return ErrInvalidPKCE
		}
		if subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) != 1 {
			return ErrInvalidPKCE
		}
		return nil
	default:
		return fmt.Errorf("oauth_provider: unsupported code_challenge_method %q", method)
	}
}
