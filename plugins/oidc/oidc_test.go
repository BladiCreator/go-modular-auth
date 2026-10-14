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
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	oidc "github.com/BladiCreator/go-modular-auth/plugins/oidc"
	"github.com/BladiCreator/go-modular-auth/plugins/oidc/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

type mockOIDCServer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	keyID      string
	issuer     string
	clientID   string
}

func newMockOIDCServer(t *testing.T, clientID string) *mockOIDCServer {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mock := &mockOIDCServer{
		privateKey: privKey,
		keyID:      "test-key-1",
		clientID:   clientID,
	}

	mux := http.NewServeMux()

	// 1. Discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := oidc.DiscoveryDocument{
			Issuer:                           mock.issuer,
			AuthorizationEndpoint:            mock.issuer + "/auth",
			TokenEndpoint:                    mock.issuer + "/token",
			JWKSUri:                          mock.issuer + "/jwks",
			UserInfoEndpoint:                 mock.issuer + "/userinfo",
			ResponseTypesSupported:           []string{"code"},
			SubjectTypesSupported:            []string{"public"},
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	// 2. JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := &privKey.PublicKey
		nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		eStr := base64.RawURLEncoding.EncodeToString(eBytes)

		jwks := oidc.JWKS{
			Keys: []oidc.JWK{
				{
					Kty: "RSA",
					Kid: mock.keyID,
					Use: "sig",
					Alg: "RS256",
					N:   nStr,
					E:   eStr,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	// 3. Token endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.Form.Get("code")

		// Code contains metadata or email for test
		sub := "google_user_98765"
		email := "alice.oidc@example.com"
		nonce := "test-nonce-123"

		if strings.Contains(code, ":") {
			parts := strings.Split(code, ":")
			sub = parts[0]
			email = parts[1]
			if len(parts) > 2 {
				nonce = parts[2]
			}
		}

		idToken := mock.createIDToken(t, sub, email, nonce, 1*time.Hour, true)

		resp := oidc.TokenResponse{
			AccessToken:  "at_test_token_12345",
			IDToken:      idToken,
			RefreshToken: "rt_test_token_67890",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mock.server = httptest.NewServer(mux)
	mock.issuer = mock.server.URL
	return mock
}

func (m *mockOIDCServer) createIDToken(t *testing.T, sub, email, nonce string, validFor time.Duration, emailVerified bool) string {
	t.Helper()
	now := time.Now().UTC()

	header := map[string]string{
		"alg": "RS256",
		"kid": m.keyID,
		"typ": "JWT",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	claims := map[string]any{
		"iss":            m.issuer,
		"sub":            sub,
		"aud":            m.clientID,
		"exp":            now.Add(validFor).Unix(),
		"iat":            now.Unix(),
		"nonce":          nonce,
		"email":          email,
		"email_verified": emailVerified,
		"name":           "Alice OIDC",
	}
	claimsBytes, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := headerB64 + "." + claimsB64
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.privateKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("failed to sign mock ID token: %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}

func setupTestAuth(t *testing.T, mock *mockOIDCServer) (*auth.Auth, plugins.OIDC) {
	t.Helper()
	adapter := adaptermem.New()
	cCache := corecache.New()

	providerCfg := oidc.ProviderConfig{
		ID:           "google",
		Issuer:       mock.issuer,
		ClientID:     mock.clientID,
		ClientSecret: "mock_client_secret_xyz",
		RedirectURI:  "https://myapp.example.com/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}

	oidcModule := oidc.New(
		oidc.WithProvider(providerCfg),
		oidc.WithHTTPClient(mock.server.Client()),
	)

	a, err := auth.New(auth.Config{
		Adapter: adapter,
		Cache:   cCache,
		Plugins: []auth.PluginModule{oidcModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	oidcCap, err := auth.Get[plugins.OIDC](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.OIDC] failed: %v", err)
	}

	return a, oidcCap
}

func TestOIDC_EndToEnd_Authentication(t *testing.T) {
	ctx := context.Background()
	mock := newMockOIDCServer(t, "test-client-id-123")
	defer mock.server.Close()

	_, oidcAuth := setupTestAuth(t, mock)

	// 1. BeginAuth
	beginRes, err := oidcAuth.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "google",
		RedirectURI: "https://myapp.example.com/callback",
	})
	if err != nil {
		t.Fatalf("BeginAuth failed: %v", err)
	}

	if beginRes.State == "" || beginRes.Nonce == "" || beginRes.CodeVerifier == "" {
		t.Fatalf("expected state, nonce, and code_verifier to be generated")
	}
	if !strings.Contains(beginRes.AuthURL, "client_id=test-client-id-123") {
		t.Errorf("AuthURL missing client_id: %s", beginRes.AuthURL)
	}
	if !strings.Contains(beginRes.AuthURL, "nonce="+beginRes.Nonce) {
		t.Errorf("AuthURL missing nonce: %s", beginRes.AuthURL)
	}

	// 2. CompleteAuth: simulate callback from OP with code
	codeWithPayload := "sub_alice_123:alice.oidc@example.com:" + beginRes.Nonce
	completeRes, err := oidcAuth.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "google",
		Code:        codeWithPayload,
		State:       beginRes.State,
		RedirectURI: "https://myapp.example.com/callback",
	})
	if err != nil {
		t.Fatalf("CompleteAuth failed: %v", err)
	}

	if !completeRes.IsNewUser {
		t.Errorf("expected IsNewUser to be true")
	}
	if completeRes.User.Email != "alice.oidc@example.com" {
		t.Errorf("unexpected email: %s", completeRes.User.Email)
	}
	if completeRes.Account.Provider != "google" || completeRes.Account.ProviderID != "sub_alice_123" {
		t.Errorf("unexpected account: %+v", completeRes.Account)
	}
	if completeRes.Token == "" || completeRes.Session == nil {
		t.Errorf("expected active session and token to be issued")
	}

	// 3. Replay protection: Re-submitting the exact same state must fail with ErrInvalidState or ErrStateConsumed
	_, err = oidcAuth.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "google",
		Code:        codeWithPayload,
		State:       beginRes.State,
		RedirectURI: "https://myapp.example.com/callback",
	})
	if !errors.Is(err, oidc.ErrStateConsumed) && !errors.Is(err, oidc.ErrInvalidState) {
		t.Fatalf("expected ErrStateConsumed on replay, got %v", err)
	}

	// 4. Second login with existing account
	beginRes2, err := oidcAuth.BeginAuth(ctx, oidc.BeginAuthInput{
		Provider:    "google",
		RedirectURI: "https://myapp.example.com/callback",
	})
	if err != nil {
		t.Fatalf("BeginAuth 2 failed: %v", err)
	}

	codeExisting := "sub_alice_123:alice.oidc@example.com:" + beginRes2.Nonce
	completeRes2, err := oidcAuth.CompleteAuth(ctx, oidc.CompleteAuthInput{
		Provider:    "google",
		Code:        codeExisting,
		State:       beginRes2.State,
		RedirectURI: "https://myapp.example.com/callback",
	})
	if err != nil {
		t.Fatalf("CompleteAuth 2 failed: %v", err)
	}
	if completeRes2.IsNewUser {
		t.Errorf("expected IsNewUser to be false on existing user")
	}
	if completeRes2.User.ID != completeRes.User.ID {
		t.Errorf("expected matching User ID %s, got %s", completeRes.User.ID, completeRes2.User.ID)
	}
}

func TestOIDC_AccountLinking_And_Unlinking(t *testing.T) {
	ctx := context.Background()
	mock := newMockOIDCServer(t, "test-client-id-123")
	defer mock.server.Close()

	a, oidcAuth := setupTestAuth(t, mock)

	// Create existing user with email and password
	signUpRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "existing@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signUpRes.User.ID

	// 1. BeginLink for existing user
	beginLinkRes, err := oidcAuth.BeginLink(ctx, oidc.BeginLinkInput{
		UserID:      userID,
		Provider:    "google",
		RedirectURI: "https://myapp.example.com/callback",
	})
	if err != nil {
		t.Fatalf("BeginLink failed: %v", err)
	}

	// 2. CompleteLink
	codeLink := "sub_google_link_999:existing@example.com:" + beginLinkRes.Nonce
	linkRes, err := oidcAuth.CompleteLink(ctx, oidc.CompleteLinkInput{
		Provider:    "google",
		Code:        codeLink,
		State:       beginLinkRes.State,
		RedirectURI: "https://myapp.example.com/callback",
	})
	if err != nil {
		t.Fatalf("CompleteLink failed: %v", err)
	}
	if linkRes.Account.UserID != userID {
		t.Errorf("expected linked account UserID %s, got %s", userID, linkRes.Account.UserID)
	}

	// 3. ListAccounts
	accounts, err := oidcAuth.ListAccounts(ctx, userID)
	if err != nil {
		t.Fatalf("ListAccounts failed: %v", err)
	}
	if len(accounts) != 1 || accounts[0].Provider != "google" {
		t.Fatalf("expected 1 linked google account, got %v", accounts)
	}

	// 4. UnlinkAccount
	err = oidcAuth.UnlinkAccount(ctx, userID, "google")
	if err != nil {
		t.Fatalf("UnlinkAccount failed: %v", err)
	}

	// Verify unlinked
	accountsAfter, _ := oidcAuth.ListAccounts(ctx, userID)
	if len(accountsAfter) != 0 {
		t.Fatalf("expected 0 accounts after unlink, got %d", len(accountsAfter))
	}
}
