package twofactor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTPAlgorithm defines the supported cryptographic hashing algorithm for RFC 6238 TOTP calculations.
type TOTPAlgorithm string

const (
	// AlgorithmSHA1 represents HMAC-SHA1 (RFC 6238 default).
	AlgorithmSHA1 TOTPAlgorithm = "SHA1"

	// AlgorithmSHA256 represents HMAC-SHA256.
	AlgorithmSHA256 TOTPAlgorithm = "SHA256"

	// AlgorithmSHA512 represents HMAC-SHA512.
	AlgorithmSHA512 TOTPAlgorithm = "SHA512"
)

const (
	// BackupCharset defines the unambiguous alfanumeric charset (excluding 0/O, 1/I/L) used for backup recovery codes.
	BackupCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// GenerateBase32Secret generates a cryptographically secure random secret encoded in RFC 4648 Base32 without padding.
func GenerateBase32Secret(byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = 20
	}
	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("twofactor: failed to generate random secret bytes: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// DecodeBase32Secret decodes a Base32 encoded secret, normalizing spaces and stripping padding.
func DecodeBase32Secret(secret string) ([]byte, error) {
	clean := strings.ToUpper(strings.TrimSpace(secret))
	clean = strings.ReplaceAll(clean, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.TrimRight(clean, "=")

	bytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		// Fallback to std decoding in case padding exists
		bytes, err = base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
		if err != nil {
			return nil, fmt.Errorf("twofactor: invalid base32 secret: %w", err)
		}
	}
	return bytes, nil
}

// getHasher returns the appropriate hash constructor for the specified TOTPAlgorithm.
func getHasher(alg TOTPAlgorithm) func() hash.Hash {
	switch strings.ToUpper(string(alg)) {
	case string(AlgorithmSHA256):
		return sha256.New
	case string(AlgorithmSHA512):
		return sha512.New
	default:
		return sha1.New
	}
}

// GenerateTOTPCode calculates the RFC 6238 TOTP code for the specified secret, timestamp, and parameters.
func GenerateTOTPCode(secret string, timestamp int64, period int, digits int, alg TOTPAlgorithm) (string, error) {
	if period <= 0 {
		period = 30
	}
	if digits != 6 && digits != 8 {
		digits = 6
	}

	secretBytes, err := DecodeBase32Secret(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(timestamp / int64(period))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	hasher := getHasher(alg)
	mac := hmac.New(hasher, secretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (int32(sum[offset]&0x7f) << 24) |
		(int32(sum[offset+1]&0xff) << 16) |
		(int32(sum[offset+2]&0xff) << 8) |
		(int32(sum[offset+3] & 0xff))

	mod := int32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}

	return fmt.Sprintf("%0*d", digits, binCode%mod), nil
}

// ValidateTOTPCode validates an incoming TOTP code against a secret across the ±1 period tolerance window.
// It executes comparison using constant-time comparison to guard against side-channel timing attacks.
func ValidateTOTPCode(secret, code string, period int, digits int, alg TOTPAlgorithm) bool {
	if code == "" || secret == "" {
		return false
	}
	if period <= 0 {
		period = 30
	}
	if digits != 6 && digits != 8 {
		digits = 6
	}

	now := time.Now().Unix()
	p := int64(period)

	for t := now - p; t <= now+p; t += p {
		expected, err := GenerateTOTPCode(secret, t, period, digits, alg)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// BuildTOTPURI constructs a RFC 6238 compliant otpauth:// URI for authenticator app QR code generation.
func BuildTOTPURI(issuer, accountName, secret string, digits, period int, alg TOTPAlgorithm) string {
	if digits != 6 && digits != 8 {
		digits = 6
	}
	if period <= 0 {
		period = 30
	}
	if alg == "" {
		alg = AlgorithmSHA1
	}

	label := url.PathEscape(accountName)
	if issuer != "" {
		label = fmt.Sprintf("%s:%s", url.PathEscape(issuer), url.PathEscape(accountName))
	}

	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&digits=%d&period=%d&algorithm=%s",
		label,
		secret,
		digits,
		period,
		string(alg),
	)

	if issuer != "" {
		uri += fmt.Sprintf("&issuer=%s", url.QueryEscape(issuer))
	}

	return uri
}

// GenerateBackupCodes creates a set of random alphanumeric single-use recovery codes formatted as XXXXX-XXXXX.
func GenerateBackupCodes(amount, length int) ([]string, error) {
	if amount <= 0 {
		amount = 10
	}
	if length <= 0 {
		length = 10
	}

	codes := make([]string, amount)
	charsetLen := big.NewInt(int64(len(BackupCharset)))

	for i := 0; i < amount; i++ {
		b := make([]byte, length)
		for j := range b {
			idx, err := rand.Int(rand.Reader, charsetLen)
			if err != nil {
				return nil, fmt.Errorf("twofactor: failed to generate backup code random character: %w", err)
			}
			b[j] = BackupCharset[idx.Int64()]
		}
		raw := string(b)
		mid := len(raw) / 2
		if mid > 0 {
			codes[i] = fmt.Sprintf("%s-%s", raw[:mid], raw[mid:])
		} else {
			codes[i] = raw
		}
	}
	return codes, nil
}

// NormalizeCode standardizes an input code by removing spaces, hyphens and converting to uppercase.
func NormalizeCode(code string) string {
	c := strings.ToUpper(strings.TrimSpace(code))
	c = strings.ReplaceAll(c, "-", "")
	c = strings.ReplaceAll(c, " ", "")
	return c
}

// ValidateBackupCode searches for the given input code within a slice of backup codes using constant-time comparison.
// Returns the index of the matching code and true if valid, or -1 and false otherwise.
func ValidateBackupCode(codes []string, inputCode string) (int, bool) {
	normalizedInput := NormalizeCode(inputCode)
	if normalizedInput == "" {
		return -1, false
	}

	foundIdx := -1
	for i, stored := range codes {
		normalizedStored := NormalizeCode(stored)
		if subtle.ConstantTimeCompare([]byte(normalizedStored), []byte(normalizedInput)) == 1 {
			foundIdx = i
			break
		}
	}

	if foundIdx != -1 {
		return foundIdx, true
	}
	return -1, false
}

// GenerateRandomNumericCode generates a cryptographically secure random numeric string of specified length.
func GenerateRandomNumericCode(digits int) (string, error) {
	if digits <= 0 {
		digits = 6
	}

	maxVal := big.NewInt(1)
	for i := 0; i < digits; i++ {
		maxVal.Mul(maxVal, big.NewInt(10))
	}

	n, err := rand.Int(rand.Reader, maxVal)
	if err != nil {
		return "", fmt.Errorf("twofactor: failed to generate random numeric code: %w", err)
	}

	return fmt.Sprintf("%0*d", digits, n.Int64()), nil
}

// GenerateRandomToken generates a cryptographically secure URL-safe random token string.
func GenerateRandomToken(byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = 32
	}
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("twofactor: failed to generate random token bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateTrustDeviceToken generates a signed cryptographic token authorizing a trusted device.
// Format: "<payload_base64>.<hmac_signature_base64>" where payload is "userID:deviceID:expiresAtUnix".
func GenerateTrustDeviceToken(userID, deviceID, secret string, expiresAt time.Time) string {
	payload := fmt.Sprintf("%s:%s:%d", userID, deviceID, expiresAt.Unix())
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payloadEncoded))
	sigEncoded := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payloadEncoded + "." + sigEncoded
}

// VerifyTrustDeviceToken validates the HMAC signature, payload structure, and expiration of a trusted device token.
func VerifyTrustDeviceToken(token, userID, deviceID, secret string) bool {
	if token == "" || secret == "" {
		return false
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}

	payloadEncoded := parts[0]
	sigProvided := parts[1]

	// Verify HMAC signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payloadEncoded))
	expectedSig := mac.Sum(nil)

	providedSigBytes, err := base64.RawURLEncoding.DecodeString(sigProvided)
	if err != nil {
		return false
	}

	if subtle.ConstantTimeCompare(expectedSig, providedSigBytes) != 1 {
		return false
	}

	// Parse payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return false
	}

	payloadParts := strings.Split(string(payloadBytes), ":")
	if len(payloadParts) != 3 {
		return false
	}

	tokenUserID := payloadParts[0]
	tokenDeviceID := payloadParts[1]
	expUnix, err := strconv.ParseInt(payloadParts[2], 10, 64)
	if err != nil {
		return false
	}

	if tokenUserID != userID || tokenDeviceID != deviceID {
		return false
	}

	if time.Now().Unix() > expUnix {
		return false
	}

	return true
}
