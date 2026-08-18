package phonenumber

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Hasher defines the contract for hashing and verifying OTP codes in constant time.
type Hasher interface {
	// Hash computes the one-way cryptographic hash of an OTP code.
	Hash(code string) (string, error)

	// Verify compares a plain text OTP against the stored hash in constant time.
	Verify(code, hashedCode string) bool
}

// Cipher defines the contract for symmetric reversible encryption of OTP codes.
type Cipher interface {
	// Encrypt encrypts a plain text OTP into a secure string representation.
	Encrypt(plaintext string) (string, error)

	// Decrypt decrypts an encrypted string back into the original plain text OTP.
	Decrypt(ciphertext string) (string, error)
}

// DefaultNumericOTPGenerator generates a cryptographically secure random numeric string of length N (default: 6).
func DefaultNumericOTPGenerator(length int) (string, error) {
	if length <= 0 {
		length = 6
	}
	const digits = "0123456789"
	maxBig := big.NewInt(int64(len(digits)))
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, maxBig)
		if err != nil {
			return "", fmt.Errorf("phonenumber: failed to generate secure random digit: %w", err)
		}
		b[i] = digits[num.Int64()]
	}
	return string(b), nil
}

// DefaultSHA256Hasher implements Hasher using SHA-256 encoded in Base64 Raw URL.
type DefaultSHA256Hasher struct{}

// Hash computes the SHA-256 hash of the plain OTP code.
func (h DefaultSHA256Hasher) Hash(code string) (string, error) {
	sum := sha256.Sum256([]byte(code))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Verify compares the plain text OTP against the stored hash using constant-time evaluation.
func (h DefaultSHA256Hasher) Verify(code, hashedCode string) bool {
	computed, err := h.Hash(code)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hashedCode)) == 1
}

// AESGCMCipher implements Cipher using AES-256-GCM with key derivation via SHA-256.
type AESGCMCipher struct {
	key []byte
}

// NewAESGCMCipher instantiates a new AES-256-GCM cipher using the provided secret key.
func NewAESGCMCipher(secretKey string) (*AESGCMCipher, error) {
	if secretKey == "" {
		return nil, errors.New("phonenumber: secret key cannot be empty for encrypted store mode")
	}
	hash := sha256.Sum256([]byte(secretKey))
	return &AESGCMCipher{key: hash[:]}, nil
}

// Encrypt encrypts the plain text OTP using AES-256-GCM and returns a Base64 Raw URL encoded string.
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
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts a Base64 Raw URL encoded ciphertext string back into the original plain text OTP.
func (c *AESGCMCipher) Decrypt(ciphertext string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(ciphertext)
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
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("phonenumber: ciphertext too short")
	}
	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}
