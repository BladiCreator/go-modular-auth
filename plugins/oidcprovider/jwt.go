package oidcprovider

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

const DefaultJWKKeyID = "oidc-provider-key-1"

// GenerateIDToken constructs and signs an OpenID Connect ID Token JWT.
func (p *Plugin) GenerateIDToken(ctx context.Context, user *entity.User, client *OAuthClient, scope string, nonce *string, accessToken *string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	exp := now.Add(expiresIn)

	claims := map[string]any{
		"iss": p.config.Issuer,
		"sub": user.ID,
		"aud": client.ClientID,
		"exp": exp.Unix(),
		"iat": now.Unix(),
	}

	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}

	if accessToken != nil && *accessToken != "" {
		h := sha256.Sum256([]byte(*accessToken))
		half := h[:len(h)/2]
		claims["at_hash"] = base64.RawURLEncoding.EncodeToString(half)
	}

	scopesList := ParseScopes(scope)

	if HasScope(scopesList, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}

	if HasScope(scopesList, "profile") {
		if user.Name != "" {
			claims["name"] = user.Name
		}
		if user.Username != "" {
			claims["preferred_username"] = user.Username
		}
		if user.DisplayUsername != "" {
			claims["nickname"] = user.DisplayUsername
		}
	}

	if p.config.GetAdditionalClaims != nil {
		additional := p.config.GetAdditionalClaims(ctx, user, scopesList, client)
		for k, v := range additional {
			claims[k] = v
		}
	}

	return p.signJWT(claims)
}

// signJWT serializes and signs a JWT map using configured RS256 or HS256 algorithm.
func (p *Plugin) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{
		"typ": "JWT",
		"alg": p.config.SigningAlgorithm,
	}

	if p.config.SigningAlgorithm == "RS256" {
		header["kid"] = DefaultJWKKeyID
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	var sigB64 string

	switch p.config.SigningAlgorithm {
	case "RS256":
		if p.config.PrivateKey == nil {
			return "", errors.New("oidcprovider: RSA private key is required for RS256 signing")
		}
		h := sha256.Sum256([]byte(signingInput))
		signature, err := rsa.SignPKCS1v15(nil, p.config.PrivateKey, crypto.SHA256, h[:])
		if err != nil {
			return "", fmt.Errorf("oidcprovider: failed to sign RSA JWT: %w", err)
		}
		sigB64 = base64.RawURLEncoding.EncodeToString(signature)

	case "HS256":
		secret := p.config.SecretKey
		if len(secret) == 0 {
			secret = []byte("default-oidc-secret-key-change-me")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signingInput))
		signature := mac.Sum(nil)
		sigB64 = base64.RawURLEncoding.EncodeToString(signature)

	default:
		return "", fmt.Errorf("oidcprovider: unsupported signing algorithm '%s'", p.config.SigningAlgorithm)
	}

	return signingInput + "." + sigB64, nil
}

// GetJWKS exports the public key set in standard JWKS JSON format.
func (p *Plugin) GetJWKS(ctx context.Context) (map[string]any, error) {
	var keys []map[string]any

	if p.config.SigningAlgorithm == "RS256" && p.config.PrivateKey != nil {
		pub := &p.config.PrivateKey.PublicKey
		nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		eStr := base64.RawURLEncoding.EncodeToString(eBytes)

		keyMap := map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": DefaultJWKKeyID,
			"n":   nStr,
			"e":   eStr,
		}
		keys = append(keys, keyMap)
	}

	return map[string]any{
		"keys": keys,
	}, nil
}

// VerifyJWT verifies a JWT token signature and decodes its claims map.
func (p *Plugin) VerifyJWT(tokenStr string) (map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidcprovider: malformed JWT token")
	}

	headerB64, claimsB64, sigB64 := parts[0], parts[1], parts[2]
	signingInput := headerB64 + "." + claimsB64

	signature, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("oidcprovider: invalid JWT signature encoding")
	}

	switch p.config.SigningAlgorithm {
	case "RS256":
		if p.config.PrivateKey == nil {
			return nil, errors.New("oidcprovider: RSA key unavailable for verification")
		}
		h := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(&p.config.PrivateKey.PublicKey, crypto.SHA256, h[:], signature); err != nil {
			return nil, errors.New("oidcprovider: RSA JWT signature verification failed")
		}

	case "HS256":
		secret := p.config.SecretKey
		if len(secret) == 0 {
			secret = []byte("default-oidc-secret-key-change-me")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signingInput))
		expectedSig := mac.Sum(nil)
		if hmac.Equal(signature, expectedSig) == false {
			return nil, errors.New("oidcprovider: HMAC JWT signature verification failed")
		}

	default:
		return nil, errors.New("oidcprovider: unsupported signing algorithm")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return nil, errors.New("oidcprovider: invalid JWT claims encoding")
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, errors.New("oidcprovider: failed to parse JWT claims")
	}

	return claims, nil
}
