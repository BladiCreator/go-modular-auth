package twofactor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SecretProtector encrypts and decrypts sensitive factor secrets at rest.
type SecretProtector interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(ciphertext string) ([]byte, error)
}

// AESGCMProtector implements SecretProtector using AES-256-GCM.
type AESGCMProtector struct {
	key []byte
}

// NewAESGCMProtector creates a new protector from a 32-byte master key.
func NewAESGCMProtector(key []byte) (*AESGCMProtector, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("twofactor: master key must be 32 bytes (got %d)", len(key))
	}
	k := make([]byte, 32)
	copy(k, key)
	return &AESGCMProtector{key: k}, nil
}

// Encrypt encrypts plaintext using AES-GCM with a random 12-byte nonce.
func (p *AESGCMProtector) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCryptoOperationFailed, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCryptoOperationFailed, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("%w: %v", ErrCryptoOperationFailed, err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(sealed), nil
}

// Decrypt decrypts a hex-encoded AES-GCM ciphertext.
func (p *AESGCMProtector) Decrypt(ciphertext string) ([]byte, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed ciphertext hex", ErrCryptoOperationFailed)
	}

	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCryptoOperationFailed, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCryptoOperationFailed, err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrCryptoOperationFailed)
	}

	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrCryptoOperationFailed)
	}

	return plaintext, nil
}

// GenerateRandomKey generates a cryptographically secure 32-byte key for AES-256.
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateTOTPSecret creates a 20-byte cryptographically secure secret, base32 encoded without padding.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("%w: %v", ErrCryptoOperationFailed, err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// CalculateTOTP generates a 6-digit TOTP code for a base32-encoded secret at a specific time step (RFC 6238 / RFC 4226).
func CalculateTOTP(secret string, step int64) (string, error) {
	// Normalize secret
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// Try standard decoding with padding if no padding failed
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", fmt.Errorf("%w: invalid base32 secret", ErrCryptoOperationFailed)
		}
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(step))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	// Dynamic truncation
	offset := h[len(h)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(h[offset : offset+4])
	binaryCode &= 0x7fffffff

	code := binaryCode % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// ValidateTOTP validates a 6-digit code against a secret within the allowed clock skew window.
// Returns the matched time step if valid, or -1 if invalid.
func ValidateTOTP(secret string, code string, now time.Time, stepDuration time.Duration, skewSteps int) (int64, bool) {
	cleanCode := strings.TrimSpace(code)
	if len(cleanCode) != 6 {
		return -1, false
	}

	currentStep := now.Unix() / int64(stepDuration.Seconds())

	for s := currentStep - int64(skewSteps); s <= currentStep+int64(skewSteps); s++ {
		expected, err := CalculateTOTP(secret, s)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(cleanCode)) == 1 {
			return s, true
		}
	}

	return -1, false
}

// BuildProvisioningURI constructs a standard otpauth://totp URI for authenticator applications.
func BuildProvisioningURI(issuer, accountName, secret string) string {
	if issuer == "" {
		issuer = "GoModularAuth"
	}
	if accountName == "" {
		accountName = "user"
	}

	label := url.PathEscape(issuer + ":" + accountName)
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", "6")
	params.Set("period", "30")

	return fmt.Sprintf("otpauth://totp/%s?%s", label, params.Encode())
}

const recoveryCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // 32 characters, excluding ambiguous 0,O,1,I

// GenerateRecoveryCode generates a formatted backup recovery code (e.g. "XXXX-XXXX-XXXX").
func GenerateRecoveryCode() (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	var sb strings.Builder
	for i := 0; i < 12; i++ {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		idx := int(bytes[i]) % len(recoveryCodeAlphabet)
		sb.WriteByte(recoveryCodeAlphabet[idx])
	}
	return sb.String(), nil
}

// NormalizeRecoveryCode cleans up user input by uppercasing and stripping hyphens and whitespaces.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(code)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return strings.TrimSpace(code)
}

// HashRecoveryCode computes the SHA-256 hash of a normalized recovery code.
func HashRecoveryCode(code string) string {
	normalized := NormalizeRecoveryCode(code)
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// GenerateRandomID generates a cryptographically secure hex ID.
func GenerateRandomID(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
