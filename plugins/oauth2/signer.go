package oauth2

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrInvalidJWT is returned when a JWT token is malformed, has invalid signature or has expired.
	ErrInvalidJWT = errors.New("oauth2/signer: invalid JWT token")

	// ErrJWTExpired is returned when a JWT token's 'exp' claim is in the past.
	ErrJWTExpired = errors.New("oauth2/signer: JWT token has expired")
)

// JWTSigner defines the contract for signing and verifying JWT tokens (ID Tokens and RFC 9068 Access Tokens).
type JWTSigner interface {
	// Sign signs the given claims map with the configured algorithm and lifetime.
	Sign(ctx context.Context, claims map[string]any, expiresIn time.Duration) (tokenString string, keyID string, err error)

	// Verify validates the JWT signature, integrity, and expiration, returning verified claims.
	Verify(ctx context.Context, tokenString string) (claims map[string]any, err error)
}

// HMACSigner is a lightweight, RFC 7519 compliant HMAC-SHA256 JWT signer.
type HMACSigner struct {
	secret []byte
	keyID  string
}

// NewHMACSigner creates a new HMAC-SHA256 JWTSigner with the specified secret and optional key ID.
func NewHMACSigner(secret string, keyID ...string) *HMACSigner {
	kid := "default-oauth2-hmac"
	if len(keyID) > 0 && keyID[0] != "" {
		kid = keyID[0]
	}
	return &HMACSigner{
		secret: []byte(secret),
		keyID:  kid,
	}
}

// Sign constructs a compact serialized JWT token ("header.payload.signature") signed with HS256.
func (s *HMACSigner) Sign(ctx context.Context, claims map[string]any, expiresIn time.Duration) (string, string, error) {
	now := time.Now().UTC()
	if claims == nil {
		claims = make(map[string]any)
	}

	// Ensure iat and exp are populated if not already present
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["exp"]; !ok && expiresIn > 0 {
		claims["exp"] = now.Add(expiresIn).Unix()
	}

	header := map[string]any{
		"typ": "JWT",
		"alg": "HS256",
		"kid": s.keyID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", "", fmt.Errorf("oauth2/signer: failed to marshal header: %w", err)
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", "", fmt.Errorf("oauth2/signer: failed to marshal payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := signingInput + "." + signatureB64
	return token, s.keyID, nil
}

// Verify decodes and validates a compact HS256 JWT string.
func (s *HMACSigner) Verify(ctx context.Context, tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWT
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidJWT
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	if subtle.ConstantTimeCompare(sigBytes, expectedSig) != 1 {
		return nil, ErrInvalidJWT
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidJWT
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, ErrInvalidJWT
	}

	// Validate expiration
	if expVal, ok := claims["exp"]; ok {
		var expUnix int64
		switch v := expVal.(type) {
		case float64:
			expUnix = int64(v)
		case int64:
			expUnix = v
		case json.Number:
			expUnix, _ = v.Int64()
		}

		if expUnix > 0 && time.Now().UTC().Unix() > expUnix {
			return nil, ErrJWTExpired
		}
	}

	return claims, nil
}
