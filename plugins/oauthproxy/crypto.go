package oauthproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidSecret    = errors.New("oauthproxy: secret key cannot be empty")
	ErrInvalidCipher    = errors.New("oauthproxy: invalid or corrupted ciphertext")
	ErrDecryptionFailed = errors.New("oauthproxy: decryption failed or secret mismatch")
)

// deriveKey derives a 32-byte AES key from an arbitrary secret string using SHA-256.
func deriveKey(secret string) ([]byte, error) {
	if secret == "" {
		return nil, ErrInvalidSecret
	}
	hash := sha256.Sum256([]byte(secret))
	return hash[:], nil
}

// Encrypt encrypts plaintext bytes using AES-256-GCM with a key derived from secret.
// The output is a URL-safe Base64 encoded string containing the 12-byte random nonce prepended to the ciphertext.
func Encrypt(secret string, plaintext []byte) (string, error) {
	key, err := deriveKey(secret)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("oauthproxy: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("oauthproxy: failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("oauthproxy: failed to generate random nonce: %w", err)
	}

	// Seal appends the encrypted plaintext and authentication tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a Base64 URL-safe ciphertext using AES-256-GCM with a key derived from secret.
func Decrypt(secret string, ciphertext string) ([]byte, error) {
	key, err := deriveKey(secret)
	if err != nil {
		return nil, err
	}

	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		// Fallback to RawURLEncoding in case padding was omitted
		var rawErr error
		data, rawErr = base64.RawURLEncoding.DecodeString(ciphertext)
		if rawErr != nil {
			return nil, fmt.Errorf("%w: invalid base64 encoding", ErrInvalidCipher)
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("oauthproxy: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("oauthproxy: failed to create GCM mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidCipher
	}

	nonce, encryptedBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedBytes, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
