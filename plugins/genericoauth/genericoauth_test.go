package genericoauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth/providers"
)

// mockRepository implements genericoauth.Repository for unit tests.
type mockRepository struct {
	mu       sync.Mutex
	users    map[string]*entity.User
	accounts map[string]*entity.Account
	sessions map[string]*entity.Session
	states   map[string]*genericoauth.StateData
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		users:    make(map[string]*entity.User),
		accounts: make(map[string]*entity.Account),
		sessions: make(map[string]*entity.Session),
		states:   make(map[string]*genericoauth.StateData),
	}
}

func (m *mockRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return nil, genericoauth.ErrUserNotFound
}

func (m *mockRepository) GetUserByID(ctx context.Context, id string) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, genericoauth.ErrUserNotFound
	}
	return u, nil
}

func (m *mockRepository) GetAccountByProvider(ctx context.Context, providerID, accountID string) (*entity.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := providerID + ":" + accountID
	acc, ok := m.accounts[key]
	if !ok {
		return nil, nil
	}
	return acc, nil
}

func (m *mockRepository) CreateUser(ctx context.Context, user *entity.User) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	return user, nil
}

func (m *mockRepository) CreateAccount(ctx context.Context, account *entity.Account) (*entity.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Stored by provider:accountID or account.ID
	m.accounts[account.Provider+":"+account.ID] = account
	return account, nil
}

func (m *mockRepository) CreateSession(ctx context.Context, session *entity.Session) (*entity.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.ID] = session
	return session, nil
}

func (m *mockRepository) SaveState(ctx context.Context, key string, data *genericoauth.StateData, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[key] = data
	return nil
}

func (m *mockRepository) GetState(ctx context.Context, key string) (*genericoauth.StateData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.states[key]
	if !ok {
		return nil, genericoauth.ErrInvalidState
	}
	return st, nil
}

func (m *mockRepository) DeleteState(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.states, key)
	return nil
}

func TestPKCEAndJWTDecoding(t *testing.T) {
	// Test PKCE generation
	verifier, challenge, err := genericoauth.GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE failed: %v", err)
	}
	if verifier == "" || challenge == "" {
		t.Fatalf("Expected non-empty PKCE verifier and challenge")
	}

	// Test DecodeIDToken
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user_123","email":"test@example.com","name":"Test User","email_verified":true}`))
	mockJWT := header + "." + payload + "."

	info, err := genericoauth.DecodeIDToken(mockJWT)
	if err != nil {
		t.Fatalf("DecodeIDToken failed: %v", err)
	}
	if info.Sub != "user_123" || info.Email != "test@example.com" || !info.EmailVerified {
		t.Errorf("Unexpected DecodeIDToken result: %+v", info)
	}
}

func TestOIDCDiscovery(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 ts.URL,
				"authorization_endpoint": ts.URL + "/authorize",
				"token_endpoint":         ts.URL + "/token",
				"userinfo_endpoint":      ts.URL + "/userinfo",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ctx := context.Background()
	doc, err := genericoauth.FetchDiscovery(ctx, ts.Client(), ts.URL+"/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatalf("FetchDiscovery failed: %v", err)
	}
	if doc.Issuer != ts.URL || doc.AuthorizationEndpoint != ts.URL+"/authorize" {
		t.Errorf("Unexpected discovery doc: %+v", doc)
	}

	provider := &genericoauth.ProviderConfig{
		ProviderID:   "custom-oidc",
		DiscoveryURL: ts.URL + "/.well-known/openid-configuration",
		ClientID:     "client_123",
	}

	err = genericoauth.ResolveProviderConfig(ctx, ts.Client(), provider)
	if err != nil {
		t.Fatalf("ResolveProviderConfig failed: %v", err)
	}
	if provider.TokenURL != ts.URL+"/token" || provider.AuthorizationURL != ts.URL+"/authorize" {
		t.Errorf("ResolveProviderConfig failed to populate endpoints: %+v", provider)
	}
}

func TestSignInAndCallbackFlow(t *testing.T) {
	var mockOAuthServer *httptest.Server
	mockOAuthServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock_access_token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            "sub_999",
				"email":          "oauth_user@example.com",
				"email_verified": true,
				"name":           "OAuth User",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockOAuthServer.Close()

	repo := newMockRepository()
	plugin := genericoauth.New(repo,
		genericoauth.WithHTTPClient(mockOAuthServer.Client()),
		genericoauth.WithProvider(&genericoauth.ProviderConfig{
			ProviderID:       "github",
			AuthorizationURL: mockOAuthServer.URL + "/authorize",
			TokenURL:         mockOAuthServer.URL + "/token",
			UserInfoURL:      mockOAuthServer.URL + "/userinfo",
			ClientID:         "client_id_x",
			ClientSecret:     "client_secret_x",
			RedirectURI:      "https://app.example.com/callback",
			PKCE:             true,
		}),
	)

	if plugin.ID() != genericoauth.PluginID {
		t.Fatalf("Expected plugin ID %s, got %s", genericoauth.PluginID, plugin.ID())
	}

	ctx := context.Background()

	// 1. SignIn
	signInData, err := plugin.SignIn(ctx, "github", "https://app.example.com/dashboard")
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}
	if signInData.State == "" || signInData.CodeVerifier == "" || !strings.Contains(signInData.URL, "code_challenge=") {
		t.Errorf("Unexpected SignInData: %+v", signInData)
	}

	// 2. Callback
	user, session, tokens, err := plugin.Callback(ctx, "github", "valid_code", signInData.State, signInData.CodeVerifier)
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}

	if user == nil || user.Email != "oauth_user@example.com" {
		t.Errorf("Unexpected user: %+v", user)
	}
	if session == nil || session.UserID != user.ID {
		t.Errorf("Unexpected session: %+v", session)
	}
	if tokens == nil || tokens.AccessToken != "mock_access_token" {
		t.Errorf("Unexpected tokens: %+v", tokens)
	}
}

func TestHTTPHandlers(t *testing.T) {
	var mockOAuthServer *httptest.Server
	mockOAuthServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "http_access_token",
				"token_type":   "Bearer",
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            "sub_http_123",
				"email":          "http_user@example.com",
				"email_verified": true,
				"name":           "HTTP User",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockOAuthServer.Close()

	repo := newMockRepository()
	plugin := genericoauth.New(repo,
		genericoauth.WithHTTPClient(mockOAuthServer.Client()),
		genericoauth.WithProvider(&genericoauth.ProviderConfig{
			ProviderID:       "google",
			AuthorizationURL: mockOAuthServer.URL + "/authorize",
			TokenURL:         mockOAuthServer.URL + "/token",
			UserInfoURL:      mockOAuthServer.URL + "/userinfo",
			ClientID:         "google_client_id",
			ClientSecret:     "google_client_secret",
			RedirectURI:      "http://localhost:8080/oauth2/callback/google",
		}),
	)

	// Test ServeSignIn
	reqSignIn := httptest.NewRequest(http.MethodGet, "/sign-in/oauth2?provider_id=google", nil)
	recSignIn := httptest.NewRecorder()
	plugin.ServeSignIn(recSignIn, reqSignIn)

	if recSignIn.Code != http.StatusOK && recSignIn.Code != http.StatusFound {
		t.Fatalf("ServeSignIn expected 200 or 302, got %d: %s", recSignIn.Code, recSignIn.Body.String())
	}

	cookies := recSignIn.Result().Cookies()
	var stateCookie string
	for _, c := range cookies {
		if c.Name == "oauth_state" {
			stateCookie, _ = url.QueryUnescape(c.Value)
		}
	}
	if stateCookie == "" {
		t.Fatalf("ServeSignIn did not set oauth_state cookie")
	}

	// Test ServeCallback
	reqCallback := httptest.NewRequest(http.MethodGet, "/oauth2/callback/google?provider_id=google&code=mock_code&state="+stateCookie, nil)
	reqCallback.AddCookie(&http.Cookie{Name: "oauth_state", Value: url.QueryEscape(stateCookie)})
	recCallback := httptest.NewRecorder()

	plugin.ServeCallback(recCallback, reqCallback)
	if recCallback.Code != http.StatusOK {
		t.Fatalf("ServeCallback expected 200, got %d: %s", recCallback.Code, recCallback.Body.String())
	}

	var cbResp map[string]any
	_ = json.Unmarshal(recCallback.Body.Bytes(), &cbResp)
	if cbResp["user"] == nil {
		t.Errorf("ServeCallback response missing user: %+v", cbResp)
	}
}

func TestProvidersHelperFunctions(t *testing.T) {
	auth0 := providers.Auth0(providers.Auth0Options{
		Domain:       "dev.auth0.com",
		ClientID:     "id",
		ClientSecret: "secret",
	})
	if auth0.ProviderID != "auth0" || auth0.DiscoveryURL != "https://dev.auth0.com/.well-known/openid-configuration" {
		t.Errorf("Unexpected Auth0 config: %+v", auth0)
	}

	kc := providers.Keycloak(providers.KeycloakOptions{
		BaseURL:  "https://kc.example.com",
		Realm:    "myrealm",
		ClientID: "id",
	})
	if kc.ProviderID != "keycloak" || !strings.Contains(kc.DiscoveryURL, "/realms/myrealm/") {
		t.Errorf("Unexpected Keycloak config: %+v", kc)
	}

	okta := providers.Okta(providers.OktaOptions{Domain: "dev.okta.com", ClientID: "id"})
	if okta.ProviderID != "okta" {
		t.Errorf("Unexpected Okta config: %+v", okta)
	}

	entra := providers.Entra(providers.EntraOptions{TenantID: "tenant_id", ClientID: "id"})
	if entra.ProviderID != "entra-id" || !strings.Contains(entra.DiscoveryURL, "tenant_id") {
		t.Errorf("Unexpected Entra config: %+v", entra)
	}

	slack := providers.Slack(providers.SlackOptions{ClientID: "id"})
	if slack.ProviderID != "slack" || slack.AuthorizationURL != "https://slack.com/openid/connect/authorize" {
		t.Errorf("Unexpected Slack config: %+v", slack)
	}

	line := providers.Line(providers.LineOptions{ClientID: "id"})
	if line.ProviderID != "line" {
		t.Errorf("Unexpected Line config: %+v", line)
	}

	hubspot := providers.HubSpot(providers.HubSpotOptions{ClientID: "id"})
	if hubspot.ProviderID != "hubspot" {
		t.Errorf("Unexpected HubSpot config: %+v", hubspot)
	}

	patreon := providers.Patreon(providers.PatreonOptions{ClientID: "id"})
	if patreon.ProviderID != "patreon" {
		t.Errorf("Unexpected Patreon config: %+v", patreon)
	}
}

func TestLinkAccount(t *testing.T) {
	var mockOAuthServer *httptest.Server
	mockOAuthServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "link_access_token",
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":   "github_user_456",
				"email": "existing@example.com",
			})
		}
	}))
	defer mockOAuthServer.Close()

	repo := newMockRepository()
	ctx := context.Background()

	// Seed existing user
	existingUser, _ := repo.CreateUser(ctx, &entity.User{
		ID:            "user_existing_123",
		Name:          "Existing User",
		Email:         "existing@example.com",
		EmailVerified: true,
	})

	plugin := genericoauth.New(repo,
		genericoauth.WithHTTPClient(mockOAuthServer.Client()),
		genericoauth.WithProvider(&genericoauth.ProviderConfig{
			ProviderID:       "github",
			AuthorizationURL: mockOAuthServer.URL + "/authorize",
			TokenURL:         mockOAuthServer.URL + "/token",
			UserInfoURL:      mockOAuthServer.URL + "/userinfo",
			ClientID:         "client_id",
		}),
	)

	account, err := plugin.LinkAccount(ctx, existingUser.ID, "github", "valid_code", "")
	if err != nil {
		t.Fatalf("LinkAccount failed: %v", err)
	}
	if account == nil || account.UserID != existingUser.ID || account.Provider != "github" {
		t.Errorf("Unexpected linked account: %+v", account)
	}
}

func TestCustomHooks(t *testing.T) {
	repo := newMockRepository()
	ctx := context.Background()

	plugin := genericoauth.New(repo,
		genericoauth.WithProvider(&genericoauth.ProviderConfig{
			ProviderID: "custom-hook-provider",
			ClientID:   "client_custom",
			GetToken: func(ctx context.Context, req genericoauth.ExchangeRequest) (*genericoauth.Tokens, error) {
				return &genericoauth.Tokens{
					AccessToken: "custom_hook_access_token",
				}, nil
			},
			GetUserInfo: func(ctx context.Context, tokens *genericoauth.Tokens) (*genericoauth.UserInfo, error) {
				return &genericoauth.UserInfo{
					ID:            "custom_sub_1",
					Email:         "hook@example.com",
					EmailVerified: true,
					Name:          "Hook User",
				}, nil
			},
		}),
	)

	user, _, tokens, err := plugin.Callback(ctx, "custom-hook-provider", "code123", "", "")
	if err != nil {
		t.Fatalf("Callback with custom hooks failed: %v", err)
	}

	if tokens.AccessToken != "custom_hook_access_token" {
		t.Errorf("Expected custom token from hook, got %s", tokens.AccessToken)
	}
	if user.Email != "hook@example.com" {
		t.Errorf("Expected user email from custom hook, got %s", user.Email)
	}
}

func TestErrorHandling(t *testing.T) {
	repo := newMockRepository()
	plugin := genericoauth.New(repo,
		genericoauth.WithProvider(&genericoauth.ProviderConfig{
			ProviderID:          "disabled-signup",
			ClientID:            "client",
			DisableImplicitSignUp: true,
			GetToken: func(ctx context.Context, req genericoauth.ExchangeRequest) (*genericoauth.Tokens, error) {
				return &genericoauth.Tokens{AccessToken: "token"}, nil
			},
			GetUserInfo: func(ctx context.Context, tokens *genericoauth.Tokens) (*genericoauth.UserInfo, error) {
				return &genericoauth.UserInfo{ID: "new_sub_99", Email: "newuser@example.com"}, nil
			},
		}),
	)

	ctx := context.Background()

	// 1. Unknown provider
	_, err := plugin.SignIn(ctx, "nonexistent", "")
	if err == nil || !strings.Contains(err.Error(), genericoauth.ErrProviderNotFound.Error()) {
		t.Errorf("Expected ErrProviderNotFound, got %v", err)
	}

	// 2. Disabled sign up
	_, _, _, err = plugin.Callback(ctx, "disabled-signup", "code", "", "")
	if err != genericoauth.ErrSignUpDisabled {
		t.Errorf("Expected ErrSignUpDisabled, got %v", err)
	}
}

