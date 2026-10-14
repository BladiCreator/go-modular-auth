package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugins/oauth/provider"
)

func TestGenericProvider_AuthCodeURL(t *testing.T) {
	p, err := provider.NewGenericProvider(provider.GenericConfig{
		Name:                "google",
		ClientID:            "client_id_123",
		ClientSecret:        "client_secret_xyz",
		AuthURL:             "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:            "https://oauth2.googleapis.com/token",
		UserInfoURL:         "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:              []string{"openid", "email"},
		AllowedRedirectURIs: []string{"https://app.com/callback"},
	})
	if err != nil {
		t.Fatalf("unexpected provider creation error: %v", err)
	}

	authURLStr := p.AuthCodeURL("state_token_123",
		provider.WithRedirectURI("https://app.com/callback"),
		provider.WithPKCE("challenge_bytes", "S256"),
		provider.WithPrompt("consent"),
		provider.WithAccessType("offline"),
	)

	parsedURL, err := url.Parse(authURLStr)
	if err != nil {
		t.Fatalf("invalid generated auth URL: %v", err)
	}

	q := parsedURL.Query()
	if q.Get("client_id") != "client_id_123" {
		t.Fatalf("expected client_id client_id_123, got %s", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("expected response_type code, got %s", q.Get("response_type"))
	}
	if q.Get("state") != "state_token_123" {
		t.Fatalf("expected state state_token_123, got %s", q.Get("state"))
	}
	if q.Get("redirect_uri") != "https://app.com/callback" {
		t.Fatalf("expected redirect_uri https://app.com/callback, got %s", q.Get("redirect_uri"))
	}
	if q.Get("scope") != "openid email" {
		t.Fatalf("expected scope 'openid email', got %s", q.Get("scope"))
	}
	if q.Get("code_challenge") != "challenge_bytes" {
		t.Fatalf("expected code_challenge challenge_bytes, got %s", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("expected code_challenge_method S256, got %s", q.Get("code_challenge_method"))
	}
	if q.Get("prompt") != "consent" {
		t.Fatalf("expected prompt consent, got %s", q.Get("prompt"))
	}
	if q.Get("access_type") != "offline" {
		t.Fatalf("expected access_type offline, got %s", q.Get("access_type"))
	}
}

func TestGenericProvider_ValidateRedirectURI(t *testing.T) {
	p, err := provider.NewGenericProvider(provider.GenericConfig{
		Name:                "test",
		ClientID:            "id",
		AuthURL:             "https://auth.com",
		TokenURL:            "https://token.com",
		AllowedRedirectURIs: []string{"https://app.com/callback", "https://staging.app.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !p.ValidateRedirectURI("https://app.com/callback") {
		t.Fatal("expected https://app.com/callback to be allowed")
	}
	if !p.ValidateRedirectURI("https://staging.app.com/callback") {
		t.Fatal("expected https://staging.app.com/callback to be allowed")
	}
	if p.ValidateRedirectURI("https://evil.com/callback") {
		t.Fatal("expected https://evil.com/callback to be rejected")
	}
	if p.ValidateRedirectURI("") {
		t.Fatal("empty redirect URI should be rejected")
	}
}

func TestGenericProvider_ExchangeAndFetchProfile(t *testing.T) {
	ctx := context.Background()

	// Mock IdP Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			_ = r.ParseForm()
			if r.FormValue("grant_type") != "authorization_code" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			if r.FormValue("code") != "valid_auth_code" {
				http.Error(w, `{"error":"invalid_code"}`, http.StatusBadRequest)
				return
			}
			if r.FormValue("code_verifier") != "test_code_verifier" {
				http.Error(w, `{"error":"invalid_pkce"}`, http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "mock_access_token_xyz",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "mock_refresh_token_abc",
				"scope":         "openid profile email",
			})

		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer mock_access_token_xyz" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            "idp_user_12345",
				"email":          "alice@example.com",
				"email_verified": true,
				"name":           "Alice Example",
				"picture":        "https://cdn.example.com/avatar.png",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	p, err := provider.NewGenericProvider(provider.GenericConfig{
		Name:                "mock_idp",
		ClientID:            "client_1",
		ClientSecret:        "secret_1",
		AuthURL:             server.URL + "/auth",
		TokenURL:            server.URL + "/token",
		UserInfoURL:         server.URL + "/userinfo",
		AllowedRedirectURIs: []string{"https://app.com/callback"},
		HTTPClient:          server.Client(),
	})
	if err != nil {
		t.Fatalf("create provider error: %v", err)
	}

	// 1. Token Exchange
	tokens, err := p.Exchange(ctx, "valid_auth_code",
		provider.WithExchangeRedirectURI("https://app.com/callback"),
		provider.WithCodeVerifier("test_code_verifier"),
	)
	if err != nil {
		t.Fatalf("unexpected exchange error: %v", err)
	}

	if tokens.AccessToken != "mock_access_token_xyz" {
		t.Fatalf("unexpected access token: %s", tokens.AccessToken)
	}
	if tokens.RefreshToken != "mock_refresh_token_abc" {
		t.Fatalf("unexpected refresh token: %s", tokens.RefreshToken)
	}
	if tokens.ExpiresIn != 3600 || tokens.Expired(time.Now()) {
		t.Fatal("token should not be expired")
	}

	// Exchange failure with invalid code
	_, err = p.Exchange(ctx, "bad_code", provider.WithCodeVerifier("test_code_verifier"))
	if err == nil {
		t.Fatal("expected error on invalid code")
	}

	// 2. Fetch Profile
	profile, err := p.FetchProfile(ctx, tokens)
	if err != nil {
		t.Fatalf("unexpected profile fetch error: %v", err)
	}

	if profile.ProviderID != "idp_user_12345" {
		t.Fatalf("expected sub idp_user_12345, got %s", profile.ProviderID)
	}
	if profile.Email != "alice@example.com" {
		t.Fatalf("expected email alice@example.com, got %s", profile.Email)
	}
	if !profile.EmailVerified {
		t.Fatal("expected email_verified true")
	}
	if profile.Name != "Alice Example" {
		t.Fatalf("expected name Alice Example, got %s", profile.Name)
	}
	if profile.AvatarURL != "https://cdn.example.com/avatar.png" {
		t.Fatalf("expected avatar url, got %s", profile.AvatarURL)
	}
}

func TestPresets(t *testing.T) {
	cfg := provider.ProviderCommonConfig{
		ClientID:     "id",
		ClientSecret: "secret",
	}

	// Google
	google, err := provider.NewGoogleProvider(cfg)
	if err != nil || google.Name() != "google" {
		t.Fatalf("google provider error: %v", err)
	}

	// GitHub
	github, err := provider.NewGitHubProvider(cfg)
	if err != nil || github.Name() != "github" {
		t.Fatalf("github provider error: %v", err)
	}

	// GitLab
	gitlab, err := provider.NewGitLabProvider("https://gitlab.com", cfg)
	if err != nil || gitlab.Name() != "gitlab" {
		t.Fatalf("gitlab provider error: %v", err)
	}

	// Discord
	discord, err := provider.NewDiscordProvider(cfg)
	if err != nil || discord.Name() != "discord" {
		t.Fatalf("discord provider error: %v", err)
	}

	// Microsoft
	ms, err := provider.NewMicrosoftProvider("common", cfg)
	if err != nil || ms.Name() != "microsoft" {
		t.Fatalf("microsoft provider error: %v", err)
	}
}
