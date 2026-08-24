package oidcprovider_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/oidcprovider"
)

type MockRepository struct {
	mu       sync.Mutex
	clients  map[string]*oidcprovider.OAuthClient
	codes    map[string]*oidcprovider.OAuthCode
	tokens   map[string]*oidcprovider.OAuthToken // key: AccessToken
	refreshs map[string]*oidcprovider.OAuthToken // key: RefreshToken
	consents map[string]*oidcprovider.OAuthConsent
	users    map[string]*entity.User
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		clients:  make(map[string]*oidcprovider.OAuthClient),
		codes:    make(map[string]*oidcprovider.OAuthCode),
		tokens:   make(map[string]*oidcprovider.OAuthToken),
		refreshs: make(map[string]*oidcprovider.OAuthToken),
		consents: make(map[string]*oidcprovider.OAuthConsent),
		users:    make(map[string]*entity.User),
	}
}

func (m *MockRepository) CreateClient(ctx context.Context, client *oidcprovider.OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *client
	m.clients[client.ClientID] = &cp
	return nil
}

func (m *MockRepository) FindByClientID(ctx context.Context, clientID string) (*oidcprovider.OAuthClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[clientID]
	if !ok {
		return nil, oidcprovider.ErrInvalidClient
	}
	cp := *c
	return &cp, nil
}

func (m *MockRepository) UpdateClient(ctx context.Context, client *oidcprovider.OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *client
	m.clients[client.ClientID] = &cp
	return nil
}

func (m *MockRepository) DeleteClient(ctx context.Context, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, clientID)
	return nil
}

func (m *MockRepository) ListClientsByUserID(ctx context.Context, userID string) ([]*oidcprovider.OAuthClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []*oidcprovider.OAuthClient
	for _, c := range m.clients {
		if c.UserID != nil && *c.UserID == userID {
			cp := *c
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *MockRepository) CreateAuthorizationCode(ctx context.Context, code *oidcprovider.OAuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *code
	m.codes[code.Code] = &cp
	return nil
}

func (m *MockRepository) ConsumeAuthorizationCode(ctx context.Context, code string) (*oidcprovider.OAuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[code]
	if !ok {
		return nil, oidcprovider.ErrInvalidGrant
	}
	if c.Consumed {
		return nil, oidcprovider.ErrCodeAlreadyConsumed
	}
	c.Consumed = true
	cp := *c
	return &cp, nil
}

func (m *MockRepository) DeleteExpiredCodes(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, c := range m.codes {
		if c.ExpiresAt.Before(now) {
			delete(m.codes, k)
		}
	}
	return nil
}

func (m *MockRepository) CreateTokenPair(ctx context.Context, token *oidcprovider.OAuthToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *token
	m.tokens[token.AccessToken] = &cp
	if token.RefreshToken != "" {
		m.refreshs[token.RefreshToken] = &cp
	}
	return nil
}

func (m *MockRepository) FindByAccessToken(ctx context.Context, accessToken string) (*oidcprovider.OAuthToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[accessToken]
	if !ok {
		return nil, oidcprovider.ErrInvalidGrant
	}
	cp := *t
	return &cp, nil
}

func (m *MockRepository) FindByRefreshToken(ctx context.Context, refreshToken string) (*oidcprovider.OAuthToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.refreshs[refreshToken]
	if !ok {
		return nil, oidcprovider.ErrInvalidGrant
	}
	cp := *t
	return &cp, nil
}

func (m *MockRepository) RevokeTokenPair(ctx context.Context, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, t := range m.tokens {
		if t.ID == tokenID {
			delete(m.tokens, k)
		}
	}
	for k, t := range m.refreshs {
		if t.ID == tokenID {
			delete(m.refreshs, k)
		}
	}
	return nil
}

func (m *MockRepository) RevokeTokensByClientIDAndUserID(ctx context.Context, clientID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, t := range m.tokens {
		if (clientID == "" || t.ClientID == clientID) && (userID == "" || t.UserID == userID) {
			delete(m.tokens, k)
		}
	}
	for k, t := range m.refreshs {
		if (clientID == "" || t.ClientID == clientID) && (userID == "" || t.UserID == userID) {
			delete(m.refreshs, k)
		}
	}
	return nil
}

func (m *MockRepository) DeleteExpiredTokens(ctx context.Context) error {
	return nil
}

func (m *MockRepository) GetConsent(ctx context.Context, clientID, userID string) (*oidcprovider.OAuthConsent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + ":" + userID
	c, ok := m.consents[key]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (m *MockRepository) SaveConsent(ctx context.Context, consent *oidcprovider.OAuthConsent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := consent.ClientID + ":" + consent.UserID
	cp := *consent
	m.consents[key] = &cp
	return nil
}

func (m *MockRepository) RevokeConsent(ctx context.Context, clientID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + ":" + userID
	delete(m.consents, key)
	return nil
}

func (m *MockRepository) GetUserByID(ctx context.Context, userID string) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil, oidcprovider.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

// -----------------------------------------------------------------------------
// Integration Tests
// -----------------------------------------------------------------------------

func TestOIDCProvider_HappyPath_PKCE(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()

	testUser := &entity.User{
		ID:            "usr_oidc_1",
		Name:          "Alice Gopher",
		Email:         "alice@golang.org",
		EmailVerified: true,
	}
	repo.users[testUser.ID] = testUser

	p := oidcprovider.New(repo,
		oidcprovider.WithIssuer("https://auth.example.com"),
		oidcprovider.WithBaseURL("https://auth.example.com"),
		oidcprovider.WithSecretKey([]byte("super-secret-key-1234567890123456")),
	)
	_ = p.Init(plugin.NewContext(nil, nil))

	// 1. Register client
	client, err := p.RegisterClient(ctx, oidcprovider.RegisterClientParams{
		Name:         "Demo Web App",
		Type:         oidcprovider.ClientTypeWeb,
		RedirectURIs: []string{"https://app.example.com/callback"},
		SkipConsent:  false,
	})
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}

	// Prepare PKCE values
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	challengeMethod := "S256"
	state := "random-state-123"

	// 2. Authorize -> Requires consent initial response
	authRes, err := p.Authorize(ctx, oidcprovider.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		Scope:               "openid profile email",
		State:               &state,
		CodeChallenge:       &codeChallenge,
		CodeChallengeMethod: &challengeMethod,
		UserID:              testUser.ID,
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	if !authRes.RequiresConsent || authRes.ConsentCode == nil {
		t.Fatalf("expected authorization to require consent")
	}

	// 3. Grant consent
	_, err = p.GrantConsent(ctx, oidcprovider.GrantConsentParams{
		ClientID:    client.ClientID,
		UserID:      testUser.ID,
		ConsentCode: *authRes.ConsentCode,
		Accept:      true,
		Scopes:      authRes.ScopesRequested,
	})
	if err != nil {
		t.Fatalf("GrantConsent failed: %v", err)
	}

	// 4. Authorize again after consent -> Issued Code
	authRes2, err := p.Authorize(ctx, oidcprovider.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		Scope:               "openid profile email",
		State:               &state,
		CodeChallenge:       &codeChallenge,
		CodeChallengeMethod: &challengeMethod,
		UserID:              testUser.ID,
	})
	if err != nil {
		t.Fatalf("Authorize after consent failed: %v", err)
	}

	if authRes2.RequiresConsent || authRes2.Code == nil {
		t.Fatalf("expected authorization code to be issued after consent")
	}

	// 5. Exchange Token with code_verifier
	redirectURI := "https://app.example.com/callback"
	tokenRes, err := p.ExchangeToken(ctx, oidcprovider.ExchangeTokenParams{
		GrantType:    oidcprovider.GrantTypeAuthorizationCode,
		Code:         authRes2.Code,
		RedirectURI:  &redirectURI,
		ClientID:     client.ClientID,
		ClientSecret: client.ClientSecret,
		CodeVerifier: &codeVerifier,
	})
	if err != nil {
		t.Fatalf("ExchangeToken failed: %v", err)
	}

	if tokenRes.AccessToken == "" || tokenRes.IDToken == "" || tokenRes.RefreshToken == "" {
		t.Errorf("expected AccessToken, RefreshToken, and IDToken in response")
	}

	// 6. GetUserInfo
	userInfo, err := p.GetUserInfo(ctx, tokenRes.AccessToken)
	if err != nil {
		t.Fatalf("GetUserInfo failed: %v", err)
	}

	if userInfo["sub"] != testUser.ID || userInfo["email"] != testUser.Email {
		t.Errorf("unexpected UserInfo claims: %+v", userInfo)
	}

	// 7. GetDiscoveryMetadata
	discovery, err := p.GetDiscoveryMetadata(ctx)
	if err != nil {
		t.Fatalf("GetDiscoveryMetadata failed: %v", err)
	}
	if discovery.Issuer != "https://auth.example.com" {
		t.Errorf("unexpected issuer in discovery: %s", discovery.Issuer)
	}
}

func TestOIDCProvider_CodeReuseRevocation(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()

	testUser := &entity.User{ID: "usr_reuse", Email: "reuse@example.com"}
	repo.users[testUser.ID] = testUser

	p := oidcprovider.New(repo, oidcprovider.WithRequirePKCE(false))
	_ = p.Init(plugin.NewContext(nil, nil))

	client, _ := p.RegisterClient(ctx, oidcprovider.RegisterClientParams{
		Name:         "Public App",
		Type:         oidcprovider.ClientTypePublic,
		RedirectURIs: []string{"https://app.example.com/cb"},
		SkipConsent:  true,
	})

	authRes, err := p.Authorize(ctx, oidcprovider.AuthorizeParams{
		ClientID:     client.ClientID,
		RedirectURI:  "https://app.example.com/cb",
		ResponseType: "code",
		Scope:        "openid",
		UserID:       testUser.ID,
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	// First exchange -> Success
	redirectURI := "https://app.example.com/cb"
	tokenRes, err := p.ExchangeToken(ctx, oidcprovider.ExchangeTokenParams{
		GrantType:   oidcprovider.GrantTypeAuthorizationCode,
		Code:        authRes.Code,
		RedirectURI: &redirectURI,
		ClientID:    client.ClientID,
	})
	if err != nil {
		t.Fatalf("First ExchangeToken failed: %v", err)
	}

	// Second exchange -> Triggers CodeReuseRevocation
	_, err = p.ExchangeToken(ctx, oidcprovider.ExchangeTokenParams{
		GrantType:   oidcprovider.GrantTypeAuthorizationCode,
		Code:        authRes.Code,
		RedirectURI: &redirectURI,
		ClientID:    client.ClientID,
	})
	if !errors.Is(err, oidcprovider.ErrCodeAlreadyConsumed) {
		t.Fatalf("expected ErrCodeAlreadyConsumed, got %v", err)
	}

	// Verify original access token was revoked
	_, err = p.GetUserInfo(ctx, tokenRes.AccessToken)
	if !errors.Is(err, oidcprovider.ErrInvalidGrant) {
		t.Fatalf("expected access token to be revoked after code reuse attempt")
	}
}

func TestOIDCProvider_RSA_JWKS(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	p := oidcprovider.New(repo, oidcprovider.WithRSAKeys(rsaKey))
	_ = p.Init(plugin.NewContext(nil, nil))

	jwks, err := p.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}

	keys, ok := jwks["keys"].([]map[string]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected 1 key in JWKS payload, got %+v", jwks)
	}

	if keys[0]["alg"] != "RS256" || keys[0]["kty"] != "RSA" {
		t.Errorf("unexpected JWK parameters: %+v", keys[0])
	}
}
