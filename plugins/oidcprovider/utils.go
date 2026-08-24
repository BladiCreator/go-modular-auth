package oidcprovider

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

// ValidatePKCE verifies a PKCE code_verifier against a code_challenge using the specified method (RFC 7636).
func ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string, allowPlain bool) bool {
	if codeVerifier == "" || codeChallenge == "" {
		return false
	}

	method := strings.ToUpper(strings.TrimSpace(codeChallengeMethod))
	if method == "" {
		method = "S256"
	}

	switch method {
	case "S256":
		h := sha256.Sum256([]byte(codeVerifier))
		computedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
		return ConstantTimeEqual(computedChallenge, codeChallenge)

	case "PLAIN":
		if !allowPlain {
			return false
		}
		return ConstantTimeEqual(codeVerifier, codeChallenge)

	default:
		return false
	}
}

// GenerateRandomString generates a cryptographically secure random string of specified length.
func GenerateRandomString(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	bytesNeeded := (length + 1) / 2
	b := make([]byte, bytesNeeded)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	res := hex.EncodeToString(b)
	if len(res) > length {
		res = res[:length]
	}
	return res, nil
}

// GenerateBase64URLToken generates a cryptographically secure base64url token string.
func GenerateBase64URLToken(bytesLength int) (string, error) {
	if bytesLength <= 0 {
		bytesLength = 32
	}
	b := make([]byte, bytesLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ConstantTimeEqual performs a constant-time comparison of two strings to prevent timing attacks.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidateRedirectURI checks if requestedURI strictly matches one of the client's registered redirect_uris.
func ValidateRedirectURI(requestedURI string, allowedURIs []string) bool {
	reqTrimmed := strings.TrimSpace(requestedURI)
	if reqTrimmed == "" {
		return false
	}

	parsedReq, err := url.Parse(reqTrimmed)
	if err != nil || !parsedReq.IsAbs() {
		return false
	}

	for _, allowed := range allowedURIs {
		allowedTrimmed := strings.TrimSpace(allowed)
		if allowedTrimmed == "" {
			continue
		}
		if reqTrimmed == allowedTrimmed {
			return true
		}
	}
	return false
}

// ParseScopes splits a space-delimited scope string into a clean slice of scope strings.
func ParseScopes(scopeStr string) []string {
	parts := strings.Fields(strings.TrimSpace(scopeStr))
	seen := make(map[string]bool)
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// NormalizeScopes joins a slice of scope strings into a single space-delimited string.
func NormalizeScopes(scopes []string) string {
	seen := make(map[string]bool)
	var clean []string
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			clean = append(clean, s)
		}
	}
	return strings.Join(clean, " ")
}

// HasScope checks whether a specific target scope is present in a scope slice.
func HasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if all requestedScopes are present in grantedScopes.
func HasAllScopes(grantedScopes, requestedScopes []string) bool {
	grantedMap := make(map[string]bool)
	for _, g := range grantedScopes {
		grantedMap[g] = true
	}
	for _, r := range requestedScopes {
		if !grantedMap[r] {
			return false
		}
	}
	return true
}
