package multisession

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// SignCookieValue generates a signed cookie string in the format "<token>.<signature>" using HMAC-SHA256.
func SignCookieValue(tokenValue, secret string) string {
	if secret == "" {
		return tokenValue
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tokenValue))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return tokenValue + "." + signature
}

// VerifyCookieValue verifies an HMAC-SHA256 signature and returns the raw token value.
// It supports optional "s:" prefix used by TypeScript signed cookie implementations.
func VerifyCookieValue(signedCookieVal, secret string) (string, error) {
	if secret == "" {
		return signedCookieVal, nil
	}

	cleaned := strings.TrimPrefix(signedCookieVal, "s:")
	parts := strings.Split(cleaned, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ErrInvalidSignature
	}

	tokenValue := parts[0]
	providedSig := parts[1]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tokenValue))
	expectedSigBytes := mac.Sum(nil)

	providedSigBytes, err := base64.RawURLEncoding.DecodeString(providedSig)
	if err != nil {
		return "", ErrInvalidSignature
	}

	if subtle.ConstantTimeCompare(expectedSigBytes, providedSigBytes) != 1 {
		return "", ErrInvalidSignature
	}

	return tokenValue, nil
}
