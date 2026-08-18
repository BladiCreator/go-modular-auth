package oauth2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// ErrDecryptionFailed is returned when ciphertext fails authenticated AES-GCM decryption or authentication tag check.
	ErrDecryptionFailed = errors.New("oauth2/crypto: decryption failed or invalid authentication tag")

	// ErrInvalidKeyLength is returned when a symmetric encryption key does not meet requirements.
	ErrInvalidKeyLength = errors.New("oauth2/crypto: invalid key length (expected 32 bytes for AES-256)")
)

// ComputeCodeChallenge computes the PKCE S256 code challenge for a given code verifier.
//
// OAuth 2.1 RFC 7636 Section 4.2 specifies:
//
//	code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
func ComputeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// VerifyPKCE validates an incoming code verifier against a stored code challenge and method.
//
// In strict OAuth 2.1 mode, only the "S256" challenge method is permitted.
// Comparison is performed using constant-time comparison to prevent timing attacks.
func VerifyPKCE(verifier, challenge, method string) bool {
	if method != CodeChallengeMethodS256 {
		return false
	}
	if strings.TrimSpace(verifier) == "" || strings.TrimSpace(challenge) == "" {
		return false
	}
	computed := ComputeCodeChallenge(verifier)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// HashToken computes a deterministic SHA-256 hash string for an access token or refresh token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// HashSecret computes a deterministic SHA-256 hash string for a client secret.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// DeriveAESKey derives a 32-byte cryptographic key for AES-256 from an arbitrary secret string.
func DeriveAESKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// Encrypt encrypts plain text data using AES-256-GCM authenticated encryption.
//
// It generates a cryptographically random 12-byte nonce and returns the concatenated
// nonce + ciphertext + GCM auth tag encoded in Base64URL without padding.
func Encrypt(plaintext []byte, key []byte) (string, error) {
	if len(key) != 32 {
		return "", ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("oauth2/crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("oauth2/crypto: failed to create GCM block: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("oauth2/crypto: failed to generate random nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts Base64URL-encoded ciphertext produced by Encrypt using AES-256-GCM.
func Decrypt(encodedCiphertext string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}

	data, err := base64.RawURLEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		var fallbackErr error
		data, fallbackErr = base64.StdEncoding.DecodeString(encodedCiphertext)
		if fallbackErr != nil {
			return nil, fmt.Errorf("oauth2/crypto: failed to base64 decode ciphertext: %w", err)
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("oauth2/crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("oauth2/crypto: failed to create GCM block: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrDecryptionFailed
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// SignOAuthQuery calculates an HMAC-SHA256 signature for interactive query parameters.
func SignOAuthQuery(query, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(query))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyOAuthQuery verifies the HMAC-SHA256 signature of an interactive query string.
func VerifyOAuthQuery(query, signature, secret string) bool {
	if strings.TrimSpace(query) == "" || strings.TrimSpace(signature) == "" || strings.TrimSpace(secret) == "" {
		return false
	}
	expected := SignOAuthQuery(query, secret)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) == 1
}

// DerivePairwiseSubject generates a deterministic pseudonymous subject identifier (sub claim)
// for a user given a sector identifier (or client redirect host) and pairwise secret.
//
// OIDC Core 1.0 Section 8.1:
//
//	sub = HMAC-SHA256(pairwiseSecret, sector_identifier + ":" + user_id)
func DerivePairwiseSubject(pairwiseSecret, sectorIdentifier, userID string) string {
	mac := hmac.New(sha256.New, []byte(pairwiseSecret))
	mac.Write([]byte(sectorIdentifier + ":" + userID))
	return hex.EncodeToString(mac.Sum(nil))
}

// ComputeLeftHash computes the OIDC at_hash or c_hash claim value for ID Tokens (RFC 7636 / OIDC Core 1.0).
//
// It takes the first 128 bits (16 bytes) of the SHA-256 hash and encodes it in Base64URL without padding.
func ComputeLeftHash(value string) string {
	h := sha256.Sum256([]byte(value))
	half := h[:len(h)/2]
	return base64.RawURLEncoding.EncodeToString(half)
}

// GenerateRandomString generates a cryptographically secure random string of specified byte length,
// encoded in Base64URL without padding.
func GenerateRandomString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("oauth2/crypto: failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
