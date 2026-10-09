package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// JWKS represents an RFC 7517 JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a cryptographic key in JSON Web Key format.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksCache struct {
	mu        sync.RWMutex
	keysets   map[string]JWKS
	updatedAt map[string]time.Time
}

func newJWKSCache() *jwksCache {
	return &jwksCache{
		keysets:   make(map[string]JWKS),
		updatedAt: make(map[string]time.Time),
	}
}

func (c *jwksCache) get(uri string, maxAge time.Duration) (JWKS, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ks, ok := c.keysets[uri]
	if !ok {
		return JWKS{}, false
	}
	if time.Since(c.updatedAt[uri]) > maxAge {
		return JWKS{}, false
	}
	return ks, true
}

func (c *jwksCache) set(uri string, ks JWKS) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keysets[uri] = ks
	c.updatedAt[uri] = time.Now()
}

// ParseAndVerifyIDToken verifies the cryptographic signature and claims of an OIDC ID token.
// CRITICAL: Never trusts unverified claims; verifies signature against JWKS before reading claims.
func ParseAndVerifyIDToken(rawToken string, cfg ProviderConfig, jwks JWKS, expectedNonce string, now time.Time) (*IDTokenClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidIDToken
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header decoding: %v", ErrInvalidIDToken, err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header unmarshal: %v", ErrInvalidIDToken, err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature decoding: %v", ErrInvalidIDToken, err)
	}

	signedData := []byte(parts[0] + "." + parts[1])

	// Verify signature
	if !cfg.InsecureSkipSignatureCheck {
		if err := verifySignature(header.Alg, header.Kid, signedData, sigBytes, jwks, cfg.ClientSecret); err != nil {
			return nil, err
		}
	}

	// Signature is valid: safely parse claims payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload decoding: %v", ErrInvalidIDToken, err)
	}

	var raw map[string]any
	if err := json.Unmarshal(payloadJSON, &raw); err != nil {
		return nil, fmt.Errorf("%w: payload unmarshal: %v", ErrInvalidIDToken, err)
	}

	claims, err := parseClaims(raw)
	if err != nil {
		return nil, err
	}

	// Validate claims against provider rules and OIDC Core 1.0 section 3.1.3.7
	skew := cfg.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}

	// 1. Issuer Validation
	if !cfg.SkipIssuerCheck {
		cleanExpected := strings.TrimRight(cfg.Issuer, "/")
		cleanActual := strings.TrimRight(claims.Issuer, "/")
		if cleanActual != cleanExpected {
			return nil, fmt.Errorf("%w: expected %q, got %q", ErrIssuerMismatch, cleanExpected, cleanActual)
		}
	}

	// 2. Audience Validation
	audMatch := false
	for _, aud := range claims.Audience {
		if aud == cfg.ClientID {
			audMatch = true
			break
		}
	}
	if !audMatch {
		return nil, fmt.Errorf("%w: client_id %q not in audience %v", ErrAudienceMismatch, cfg.ClientID, claims.Audience)
	}
	if len(claims.Audience) > 1 {
		if claims.AuthorizedParty != "" && claims.AuthorizedParty != cfg.ClientID {
			return nil, fmt.Errorf("%w: azp %q mismatch", ErrAudienceMismatch, claims.AuthorizedParty)
		}
	}

	// 3. Expiration Validation
	if !now.Before(claims.ExpiresAt.Add(skew)) {
		return nil, ErrTokenExpired
	}

	// 4. Nonce Validation
	if expectedNonce != "" {
		if claims.Nonce != expectedNonce {
			return nil, fmt.Errorf("%w: expected %q, got %q", ErrNonceMismatch, expectedNonce, claims.Nonce)
		}
	}

	return claims, nil
}

func verifySignature(alg, kid string, signedData, sigBytes []byte, jwks JWKS, clientSecret string) error {
	if alg == "HS256" {
		if clientSecret == "" {
			return errors.New("oidc: client_secret required for HS256 signature verification")
		}
		mac := hmac.New(sha256.New, []byte(clientSecret))
		mac.Write(signedData)
		expected := mac.Sum(nil)
		if !hmac.Equal(sigBytes, expected) {
			return ErrSignatureInvalid
		}
		return nil
	}

	key, err := findPublicKey(kid, alg, jwks)
	if err != nil {
		return err
	}

	switch alg {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("oidc: expected RSA public key")
		}
		h := sha256.Sum256(signedData)
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, h[:], sigBytes); err != nil {
			return ErrSignatureInvalid
		}
		return nil

	case "RS512":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("oidc: expected RSA public key")
		}
		h := sha512.Sum512(signedData)
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA512, h[:], sigBytes); err != nil {
			return ErrSignatureInvalid
		}
		return nil

	case "ES256":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("oidc: expected ECDSA public key")
		}
		h := sha256.Sum256(signedData)
		if !verifyECSignature(ecKey, h[:], sigBytes) {
			return ErrSignatureInvalid
		}
		return nil

	default:
		return fmt.Errorf("oidc: unsupported signing algorithm: %s", alg)
	}
}

func verifyECSignature(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	// First try standard ASN.1 format
	if ecdsa.VerifyASN1(pub, hash, sig) {
		return true
	}
	// Fall back to IEEE P1363 (concatenated R || S)
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) == 2*byteLen {
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		return ecdsa.Verify(pub, hash, r, s)
	}
	return false
}

func findPublicKey(kid, alg string, jwks JWKS) (crypto.PublicKey, error) {
	for _, jwk := range jwks.Keys {
		if kid != "" && jwk.Kid != kid {
			continue
		}
		if alg != "" && jwk.Alg != "" && jwk.Alg != alg {
			continue
		}

		switch jwk.Kty {
		case "RSA":
			pub, err := parseRSAPublicKey(jwk)
			if err == nil {
				return pub, nil
			}
		case "EC":
			pub, err := parseECPublicKey(jwk)
			if err == nil {
				return pub, nil
			}
		}
	}
	return nil, ErrKeyNotFound
}

func parseRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseECPublicKey(jwk JWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func parseClaims(raw map[string]any) (*IDTokenClaims, error) {
	c := &IDTokenClaims{
		RawClaims: raw,
	}

	if s, ok := raw["iss"].(string); ok {
		c.Issuer = s
	}
	if s, ok := raw["sub"].(string); ok {
		c.Subject = s
	}
	if s, ok := raw["nonce"].(string); ok {
		c.Nonce = s
	}
	if s, ok := raw["azp"].(string); ok {
		c.AuthorizedParty = s
	}
	if s, ok := raw["email"].(string); ok {
		c.Email = s
	}
	if b, ok := raw["email_verified"].(bool); ok {
		c.EmailVerified = b
	}
	if s, ok := raw["name"].(string); ok {
		c.Name = s
	}
	if s, ok := raw["preferred_username"].(string); ok {
		c.PreferredUsername = s
	}
	if s, ok := raw["picture"].(string); ok {
		c.Picture = s
	}

	// Audience can be string or []any
	switch aud := raw["aud"].(type) {
	case string:
		c.Audience = []string{aud}
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok {
				c.Audience = append(c.Audience, s)
			}
		}
	case []string:
		c.Audience = aud
	}

	// Expiration
	if expNum, ok := raw["exp"].(float64); ok {
		c.ExpiresAt = time.Unix(int64(expNum), 0).UTC()
	}
	if iatNum, ok := raw["iat"].(float64); ok {
		c.IssuedAt = time.Unix(int64(iatNum), 0).UTC()
	}
	if authNum, ok := raw["auth_time"].(float64); ok {
		t := time.Unix(int64(authNum), 0).UTC()
		c.AuthTime = &t
	}

	if c.Subject == "" {
		return nil, fmt.Errorf("%w: missing required sub claim", ErrInvalidIDToken)
	}

	return c, nil
}
