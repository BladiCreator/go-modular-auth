package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	oidc "github.com/BladiCreator/go-modular-auth/plugins/oidc"
	"github.com/BladiCreator/go-modular-auth/plugins/oidc/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func setupSecurityHarness(t *testing.T, customPolicy oidc.LinkingPolicy, tokenOverride func(mock *mockOIDCServer, code string) string) (*auth.Auth, plugins.OIDC, *mockOIDCServer) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	clientID := "security-client-id"
	mock := &mockOIDCServer{
		privateKey: privKey,
		keyID:      "sec-key-1",
		clientID:   clientID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := oidc.DiscoveryDocument{
			Issuer:                           mock.issuer,
			AuthorizationEndpoint:            mock.issuer + "/auth",
			TokenEndpoint:                    mock.issuer + "/token",
			JWKSUri:                          mock.issuer + "/jwks",
			ResponseTypesSupported:           []string{"code"},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := &privKey.PublicKey
		nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwks := oidc.JWKS{
			Keys: []oidc.JWK{
				{
					Kty: "RSA",
					Kid: mock.keyID,
					Use: "sig",
					Alg: "RS256",
					N:   nStr,
					E:   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.Form.Get("code")

		var idToken string
		if tokenOverride != nil {
			idToken = tokenOverride(mock, code)
		} else {
			idToken = mock.createIDToken(t, "sub-sec-1", "sec@example.com", "valid-nonce", 1*time.Hour, true)
		}

		resp := oidc.TokenResponse{
			AccessToken: "sec-access-token",
			IDToken:     idToken,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mock.server = httptest.NewServer(mux)
	mock.issuer = mock.server.URL

	adapter := adaptermem.New()
	cCache := corecache.New()

	providerCfg := oidc.ProviderConfig{
		ID:           "test-idp",
		Issuer:       mock.issuer,
		ClientID:     clientID,
		ClientSecret: "sec_secret_123",
		RedirectURI:  "https://app.example.com/cb",
		Scopes:       []string{"openid", "email"},
	}

	opts := []oidc.Option{
		oidc.WithProvider(providerCfg),
		oidc.WithHTTPClient(mock.server.Client()),
	}
	if customPolicy != "" {
		opts = append(opts, oidc.WithLinkingPolicy(customPolicy))
	}

	oidcModule := oidc.New(opts...)
	a, err := auth.New(auth.Config{
		Adapter: adapter,
		Cache:   cCache,
		Plugins: []auth.PluginModule{oidcModule},
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	oidcCap, err := auth.Get[plugins.OIDC](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.OIDC]: %v", err)
	}

	return a, oidcCap, mock
}

func TestOIDC_Security_InvalidSignature(t *testing.T) {
	ctx := context.Background()

	// Forge token with another key not in JWKS
	rogueKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tokenFunc := func(mock *mockOIDCServer, code string) string {
		now := time.Now().UTC()
		headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": mock.keyID})
		claimsBytes, _ := json.Marshal(map[string]any{
			"iss":   mock.issuer,
			"sub":   "hacker_sub",
			"aud":   mock.clientID,
			"exp":   now.Add(time.Hour).Unix(),
			"iat":   now.Unix(),
			"nonce": code,
			"email": "hacker@example.com",
		})
		hB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
		cB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)
		input := hB64 + "." + cB64
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, rogueKey, crypto.SHA256, h[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	_, oidcCap, mock := setupSecurityHarness(t, "", tokenFunc)
	defer mock.server.Close()

	beginRes, err := oidcCap.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "test-idp",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	_, err = oidcCap.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "test-idp",
		Code:        beginRes.Nonce,
		State:       beginRes.State,
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, oidc.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestOIDC_Security_IssuerMismatch(t *testing.T) {
	ctx := context.Background()

	tokenFunc := func(mock *mockOIDCServer, code string) string {
		now := time.Now().UTC()
		headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": mock.keyID})
		claimsBytes, _ := json.Marshal(map[string]any{
			"iss":   "https://malicious-issuer.attacker.com",
			"sub":   "sub_123",
			"aud":   mock.clientID,
			"exp":   now.Add(time.Hour).Unix(),
			"iat":   now.Unix(),
			"nonce": code,
		})
		hB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
		cB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)
		input := hB64 + "." + cB64
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, mock.privateKey, crypto.SHA256, h[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	_, oidcCap, mock := setupSecurityHarness(t, "", tokenFunc)
	defer mock.server.Close()

	beginRes, err := oidcCap.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "test-idp",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	_, err = oidcCap.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "test-idp",
		Code:        beginRes.Nonce,
		State:       beginRes.State,
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, oidc.ErrIssuerMismatch) {
		t.Fatalf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestOIDC_Security_AudienceMismatch(t *testing.T) {
	ctx := context.Background()

	tokenFunc := func(mock *mockOIDCServer, code string) string {
		now := time.Now().UTC()
		headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": mock.keyID})
		claimsBytes, _ := json.Marshal(map[string]any{
			"iss":   mock.issuer,
			"sub":   "sub_123",
			"aud":   "unauthorized-client-audience",
			"exp":   now.Add(time.Hour).Unix(),
			"iat":   now.Unix(),
			"nonce": code,
		})
		hB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
		cB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)
		input := hB64 + "." + cB64
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, mock.privateKey, crypto.SHA256, h[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	_, oidcCap, mock := setupSecurityHarness(t, "", tokenFunc)
	defer mock.server.Close()

	beginRes, err := oidcCap.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "test-idp",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	_, err = oidcCap.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "test-idp",
		Code:        beginRes.Nonce,
		State:       beginRes.State,
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, oidc.ErrAudienceMismatch) {
		t.Fatalf("expected ErrAudienceMismatch, got %v", err)
	}
}

func TestOIDC_Security_NonceMismatch(t *testing.T) {
	ctx := context.Background()

	tokenFunc := func(mock *mockOIDCServer, code string) string {
		now := time.Now().UTC()
		headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": mock.keyID})
		claimsBytes, _ := json.Marshal(map[string]any{
			"iss":   mock.issuer,
			"sub":   "sub_123",
			"aud":   mock.clientID,
			"exp":   now.Add(time.Hour).Unix(),
			"iat":   now.Unix(),
			"nonce": "evil-attacker-injected-nonce",
		})
		hB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
		cB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)
		input := hB64 + "." + cB64
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, mock.privateKey, crypto.SHA256, h[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	_, oidcCap, mock := setupSecurityHarness(t, "", tokenFunc)
	defer mock.server.Close()

	beginRes, err := oidcCap.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "test-idp",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	_, err = oidcCap.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "test-idp",
		Code:        beginRes.Nonce,
		State:       beginRes.State,
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, oidc.ErrNonceMismatch) {
		t.Fatalf("expected ErrNonceMismatch, got %v", err)
	}
}

func TestOIDC_Security_TokenExpired(t *testing.T) {
	ctx := context.Background()

	tokenFunc := func(mock *mockOIDCServer, code string) string {
		past := time.Now().UTC().Add(-10 * time.Minute)
		headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": mock.keyID})
		claimsBytes, _ := json.Marshal(map[string]any{
			"iss":   mock.issuer,
			"sub":   "sub_123",
			"aud":   mock.clientID,
			"exp":   past.Unix(),
			"iat":   past.Add(-5 * time.Minute).Unix(),
			"nonce": code,
		})
		hB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
		cB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)
		input := hB64 + "." + cB64
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, mock.privateKey, crypto.SHA256, h[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	_, oidcCap, mock := setupSecurityHarness(t, "", tokenFunc)
	defer mock.server.Close()

	beginRes, err := oidcCap.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "test-idp",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	_, err = oidcCap.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "test-idp",
		Code:        beginRes.Nonce,
		State:       beginRes.State,
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, oidc.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestOIDC_Security_UnverifiedEmailLinkingProhibited(t *testing.T) {
	ctx := context.Background()

	tokenFunc := func(mock *mockOIDCServer, code string) string {
		now := time.Now().UTC()
		headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": mock.keyID})
		claimsBytes, _ := json.Marshal(map[string]any{
			"iss":            mock.issuer,
			"sub":            "sub_unverified_email",
			"aud":            mock.clientID,
			"exp":            now.Add(time.Hour).Unix(),
			"iat":            now.Unix(),
			"nonce":          code,
			"email":          "victim@example.com",
			"email_verified": false, // UNVERIFIED!
		})
		hB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
		cB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)
		input := hB64 + "." + cB64
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, mock.privateKey, crypto.SHA256, h[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	a, oidcCap, mock := setupSecurityHarness(t, oidc.LinkingPolicyVerifiedEmail, tokenFunc)
	defer mock.server.Close()

	// Existing user in core with victim@example.com
	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "victim@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	beginRes, err := oidcCap.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "test-idp",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	_, err = oidcCap.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "test-idp",
		Code:        beginRes.Nonce,
		State:       beginRes.State,
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, oidc.ErrUnverifiedEmailLinkingProhibited) {
		t.Fatalf("expected ErrUnverifiedEmailLinkingProhibited, got %v", err)
	}
}

func TestOIDC_Security_CannotUnlinkLastAccount(t *testing.T) {
	ctx := context.Background()

	tokenFunc := func(mock *mockOIDCServer, code string) string {
		return mock.createIDToken(t, "sub_only_one", "onlyone@example.com", code, time.Hour, true)
	}

	_, oidcCap, mock := setupSecurityHarness(t, "", tokenFunc)
	defer mock.server.Close()

	beginRes, err := oidcCap.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "test-idp",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	res, err := oidcCap.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "test-idp",
		Code:        beginRes.Nonce,
		State:       beginRes.State,
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("CompleteAuth: %v", err)
	}

	// This user only registered via OIDC (has no password and no other accounts)
	err = oidcCap.UnlinkAccount(ctx, res.User.ID, "test-idp")
	if !errors.Is(err, oidc.ErrCannotUnlinkSoleAuthMethod) {
		t.Fatalf("expected ErrCannotUnlinkSoleAuthMethod, got %v", err)
	}
}

func TestOIDC_Security_ExplicitLinkingOnly(t *testing.T) {
	ctx := context.Background()

	tokenFunc := func(mock *mockOIDCServer, code string) string {
		return mock.createIDToken(t, "sub_collision", "target@example.com", code, time.Hour, true)
	}

	a, oidcCap, mock := setupSecurityHarness(t, oidc.LinkingPolicyExplicitOnly, tokenFunc)
	defer mock.server.Close()

	// Create user with target@example.com
	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "target@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	beginRes, err := oidcCap.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "test-idp",
		RedirectURI: "https://app.example.com/cb",
	})
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	_, err = oidcCap.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "test-idp",
		Code:        beginRes.Nonce,
		State:       beginRes.State,
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, oidc.ErrAccountLinkingRequiresConsent) {
		t.Fatalf("expected ErrAccountLinkingRequiresConsent, got %v", err)
	}
}
