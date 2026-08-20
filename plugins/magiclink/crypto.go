package magiclink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Hasher defines the contract for hashing and verifying magic link tokens in constant time.
type Hasher interface {
	// Hash computes the one-way cryptographic hash of a token.
	Hash(token string) (string, error)

	// Verify compares a plain text token against the stored hash in constant time.
	Verify(token, hashed string) bool
}

// Cipher defines the contract for symmetric reversible encryption of tokens.
type Cipher interface {
	// Encrypt encrypts a plain text token into a secure string representation.
	Encrypt(token string) (string, error)

	// Decrypt decrypts an encrypted string back into the original plain text token.
	Decrypt(encrypted string) (string, error)
}

// DefaultTokenGenerator generates a cryptographically secure random 32-byte hex token string (64 characters).
func DefaultTokenGenerator(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("magiclink: failed to generate secure random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// DefaultSHA256Hasher implements Hasher using SHA-256 encoded in Base64 Raw URL.
type DefaultSHA256Hasher struct{}

// Hash computes the SHA-256 hash of the plain token.
func (h DefaultSHA256Hasher) Hash(token string) (string, error) {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// Verify compares the plain text token against the stored hash using constant-time evaluation.
func (h DefaultSHA256Hasher) Verify(token, hashed string) bool {
	computed, err := h.Hash(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hashed)) == 1
}

// AESGCMCipher implements Cipher using AES-256-GCM with key derivation via SHA-256.
type AESGCMCipher struct {
	key []byte
}

// NewAESGCMCipher instantiates a new AES-256-GCM cipher using the provided secret key.
func NewAESGCMCipher(secretKey string) (*AESGCMCipher, error) {
	if secretKey == "" {
		return nil, errors.New("magiclink: secret key cannot be empty for encrypted store mode")
	}
	hash := sha256.Sum256([]byte(secretKey))
	return &AESGCMCipher{key: hash[:]}, nil
}

// Encrypt encrypts the plain text token using AES-256-GCM and returns a Base64 Raw URL encoded string.
func (c *AESGCMCipher) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a Base64 Raw URL encoded ciphertext string back into the original plain text token.
func (c *AESGCMCipher) Decrypt(encrypted string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("magiclink: malformed ciphertext")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
