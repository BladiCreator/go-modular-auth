package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const (
	// PKCEMethodS256 is the standard SHA-256 PKCE code challenge method.
	PKCEMethodS256 = "S256"

	// PKCEMethodPlain is the plain text PKCE method (RFC 7636 allows it, but S256 is strictly preferred).
	PKCEMethodPlain = "plain"

	// DefaultVerifierByteLength generates 32 bytes of entropy, producing 43 base64url characters.
	DefaultVerifierByteLength = 32
)

// PKCEPair holds the generated code verifier, challenge, and method according to RFC 7636.
type PKCEPair struct {
	Verifier  string `json:"verifier"`
	Challenge string `json:"challenge"`
	Method    string `json:"method"`
}

// GeneratePKCE creates a cryptographically secure PKCE code verifier and S256 code challenge.
func GeneratePKCE() (*PKCEPair, error) {
	bytes := make([]byte, DefaultVerifierByteLength)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("oauth: failed to generate pkce entropy: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(bytes)
	challenge := ComputeS256Challenge(verifier)

	return &PKCEPair{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    PKCEMethodS256,
	}, nil
}

// ComputeS256Challenge calculates the BASE64URL-ENCODED SHA-256 challenge from a code verifier.
func ComputeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// VerifyPKCE validates that a code verifier matches the code challenge using the specified method.
func VerifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" {
		return false
	}

	switch method {
	case PKCEMethodS256:
		expected := ComputeS256Challenge(verifier)
		return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
	case PKCEMethodPlain:
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	default:
		return false
	}
}
