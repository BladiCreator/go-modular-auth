// Package oidc implements the OpenID Connect protocol connector for enterprise SSO.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCConfig contains OpenID Connect specific parameters.
type OIDCConfig struct {
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	RedirectURI     string   `json:"redirect_uri"`
	Scopes          []string `json:"scopes"`
	DiscoveryURL    string   `json:"discovery_url,omitempty"`
	SkipIssuerCheck bool     `json:"skip_issuer_check,omitempty"`
}

var (
	ErrDiscoveryFailed   = errors.New("sso oidc: provider discovery failed")
	ErrTokenExchange     = errors.New("sso oidc: token exchange failed")
	ErrInvalidIDToken    = errors.New("sso oidc: invalid id_token")
	ErrSignatureInvalid  = errors.New("sso oidc: id_token signature invalid")
	ErrIssuerMismatch    = errors.New("sso oidc: issuer mismatch")
	ErrAudienceMismatch  = errors.New("sso oidc: audience mismatch")
	ErrNonceMismatch     = errors.New("sso oidc: nonce mismatch")
	ErrTokenExpired      = errors.New("sso oidc: token expired")
	ErrKeyNotFound       = errors.New("sso oidc: signing key not found in jwks")
)

type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSUri               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

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

// HTTPClient abstracts outbound HTTP request execution.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	httpClient HTTPClient
	mu         sync.RWMutex
	jwksCache  map[string]cachedJWKS
}

type cachedJWKS struct {
	jwks      *JWKS
	expiresAt time.Time
}

func NewClient(httpClient HTTPClient) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		httpClient: httpClient,
		jwksCache:  make(map[string]cachedJWKS),
	}
}

// GeneratePKCE creates an RFC 7636 code verifier and S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// GenerateNonce creates a secure random nonce string.
func GenerateNonce() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Discover fetches the OpenID Connect discovery document.
func (c *Client) Discover(ctx context.Context, issuer, discoveryURL string) (*DiscoveryDocument, error) {
	targetURL := discoveryURL
	if targetURL == "" {
		targetURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrDiscoveryFailed, resp.StatusCode)
	}

	var doc DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: parse error: %v", ErrDiscoveryFailed, err)
	}
	return &doc, nil
}

// BuildAuthURL constructs the provider authorization URL with PKCE and Nonce.
func (c *Client) BuildAuthURL(authEndpoint string, cfg *OIDCConfig, state, nonce, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	if strings.Contains(authEndpoint, "?") {
		return authEndpoint + "&" + q.Encode()
	}
	return authEndpoint + "?" + q.Encode()
}

// TokenResponse models the OIDC token endpoint response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ExchangeCode exchanges an authorization code for tokens.
func (c *Client) ExchangeCode(ctx context.Context, tokenEndpoint string, cfg *OIDCConfig, code, verifier, redirectURI string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", cfg.ClientID)
	data.Set("code_verifier", verifier)
	if cfg.ClientSecret != "" {
		data.Set("client_secret", cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s", ErrTokenExchange, resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: parse response: %v", ErrTokenExchange, err)
	}
	return &tr, nil
}

// FetchJWKS gets provider JWKS with caching.
func (c *Client) FetchJWKS(ctx context.Context, jwksURI string) (*JWKS, error) {
	now := time.Now().UTC()
	c.mu.RLock()
	cached, ok := c.jwksCache[jwksURI]
	c.mu.RUnlock()
	if ok && now.Before(cached.expiresAt) {
		return cached.jwks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}

	var set JWKS
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.jwksCache[jwksURI] = cachedJWKS{jwks: &set, expiresAt: now.Add(1 * time.Hour)}
	c.mu.Unlock()

	return &set, nil
}

type IDTokenClaims struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	Audience  []string       `json:"aud"`
	ExpiresAt time.Time      `json:"exp"`
	IssuedAt  time.Time      `json:"iat"`
	Nonce     string         `json:"nonce"`
	Email     string         `json:"email"`
	Name      string         `json:"name"`
	Raw       map[string]any `json:"-"`
}

// VerifyIDToken strictly verifies signature, issuer, audience, expiration, and nonce.
func (c *Client) VerifyIDToken(rawToken string, jwks *JWKS, cfg *OIDCConfig, expectedNonce string, now time.Time) (*IDTokenClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: token must have 3 segments", ErrInvalidIDToken)
	}

	// 1. Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header base64: %v", ErrInvalidIDToken, err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header json: %v", ErrInvalidIDToken, err)
	}

	// 2. Decode signature
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature base64: %v", ErrInvalidIDToken, err)
	}

	signedData := []byte(parts[0] + "." + parts[1])

	// 3. Verify signature
	if err := verifySignature(header.Alg, header.Kid, signedData, sig, jwks, cfg.ClientSecret); err != nil {
		return nil, err
	}

	// 4. Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload base64: %v", ErrInvalidIDToken, err)
	}

	var raw map[string]any
	if err := json.Unmarshal(payloadJSON, &raw); err != nil {
		return nil, fmt.Errorf("%w: payload json: %v", ErrInvalidIDToken, err)
	}

	// 5. Extract claims
	claims := &IDTokenClaims{Raw: raw}
	if iss, ok := raw["iss"].(string); ok {
		claims.Issuer = iss
	}
	if sub, ok := raw["sub"].(string); ok {
		claims.Subject = sub
	}
	if nonce, ok := raw["nonce"].(string); ok {
		claims.Nonce = nonce
	}
	if email, ok := raw["email"].(string); ok {
		claims.Email = email
	}
	if name, ok := raw["name"].(string); ok {
		claims.Name = name
	}
	if exp, ok := raw["exp"].(float64); ok {
		claims.ExpiresAt = time.Unix(int64(exp), 0).UTC()
	}
	if iat, ok := raw["iat"].(float64); ok {
		claims.IssuedAt = time.Unix(int64(iat), 0).UTC()
	}

	switch v := raw["aud"].(type) {
	case string:
		claims.Audience = []string{v}
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				claims.Audience = append(claims.Audience, s)
			}
		}
	}

	// 6. Validate Issuer
	if !cfg.SkipIssuerCheck {
		expIss := strings.TrimRight(cfg.Issuer, "/")
		actIss := strings.TrimRight(claims.Issuer, "/")
		if expIss != actIss {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrIssuerMismatch, expIss, actIss)
		}
	}

	// 7. Validate Audience
	audValid := false
	for _, aud := range claims.Audience {
		if aud == cfg.ClientID {
			audValid = true
			break
		}
	}
	if !audValid {
		return nil, fmt.Errorf("%w: expected client_id %s in aud %v", ErrAudienceMismatch, cfg.ClientID, claims.Audience)
	}

	// 8. Validate Expiration (with 1m clock skew)
	if claims.ExpiresAt.Add(1 * time.Minute).Before(now) {
		return nil, fmt.Errorf("%w: expired at %v", ErrTokenExpired, claims.ExpiresAt)
	}

	// 9. Validate Nonce
	if expectedNonce != "" {
		if claims.Nonce != expectedNonce {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrNonceMismatch, expectedNonce, claims.Nonce)
		}
	}

	return claims, nil
}

func verifySignature(alg, kid string, signedData, sig []byte, jwks *JWKS, clientSecret string) error {
	switch alg {
	case "HS256":
		h := hmac.New(sha256.New, []byte(clientSecret))
		h.Write(signedData)
		if !hmac.Equal(sig, h.Sum(nil)) {
			return ErrSignatureInvalid
		}
		return nil

	case "RS256", "RS512":
		key, err := findKey(jwks, kid)
		if err != nil {
			return err
		}
		rsaPub, err := parseRSAPublicKey(key)
		if err != nil {
			return fmt.Errorf("%w: parse RSA public key: %v", ErrSignatureInvalid, err)
		}
		var hash crypto.Hash
		var digest []byte
		if alg == "RS256" {
			hash = crypto.SHA256
			h := sha256.Sum256(signedData)
			digest = h[:]
		} else {
			hash = crypto.SHA512
			h := sha512.Sum512(signedData)
			digest = h[:]
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, hash, digest, sig); err != nil {
			return fmt.Errorf("%w: RSA verification: %v", ErrSignatureInvalid, err)
		}
		return nil

	case "ES256":
		key, err := findKey(jwks, kid)
		if err != nil {
			return err
		}
		ecPub, err := parseECDSAPublicKey(key)
		if err != nil {
			return fmt.Errorf("%w: parse ECDSA public key: %v", ErrSignatureInvalid, err)
		}
		h := sha256.Sum256(signedData)
		if len(sig) != 64 {
			return fmt.Errorf("%w: invalid ES256 signature length %d", ErrSignatureInvalid, len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecPub, h[:], r, s) {
			return ErrSignatureInvalid
		}
		return nil

	default:
		return fmt.Errorf("%w: unsupported alg %s", ErrSignatureInvalid, alg)
	}
}

func findKey(jwks *JWKS, kid string) (*JWK, error) {
	if jwks == nil {
		return nil, ErrKeyNotFound
	}
	if kid != "" {
		for i := range jwks.Keys {
			if jwks.Keys[i].Kid == kid {
				return &jwks.Keys[i], nil
			}
		}
	}
	if len(jwks.Keys) == 1 {
		return &jwks.Keys[0], nil
	}
	return nil, ErrKeyNotFound
}

func parseRSAPublicKey(k *JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	var eInt int
	for _, b := range eBytes {
		eInt = (eInt << 8) | int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

func parseECDSAPublicKey(k *JWK) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
