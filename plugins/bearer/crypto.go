package bearer

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strings"
)

// SignToken generates a signed token string in the format "<raw_token>.<base64url_signature>" using HMAC-SHA256.
func SignToken(tokenValue, secret string) string {
	if secret == "" {
		return tokenValue
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tokenValue))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return tokenValue + "." + signature
}

// VerifyToken validates the HMAC-SHA256 signature of a signed token ("<value>.<signature>").
// It uses subtle.ConstantTimeCompare to protect against timing attacks.
func VerifyToken(signedToken, secret string) (string, error) {
	if secret == "" {
		return "", ErrSecretRequired
	}

	parts := strings.Split(signedToken, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ErrInvalidTokenFormat
	}

	tokenValue := parts[0]
	providedSig := parts[1]

	expectedSigBytes := computeHMAC(tokenValue, secret)
	providedSigBytes, err := base64.RawURLEncoding.DecodeString(providedSig)
	if err != nil {
		return "", ErrInvalidSignature
	}

	if subtle.ConstantTimeCompare(expectedSigBytes, providedSigBytes) != 1 {
		return "", ErrInvalidSignature
	}

	return tokenValue, nil
}

// computeHMAC generates raw HMAC-SHA256 digest bytes for the given message and secret.
func computeHMAC(message, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// TryDecodeToken attempts to unescape percent-encoded characters (%2E, %2B) present in tokens.
func TryDecodeToken(token string) string {
	if !strings.Contains(token, "%") {
		return token
	}
	decoded, err := url.QueryUnescape(token)
	if err != nil {
		return token
	}
	return decoded
}
