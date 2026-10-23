package oauthprovider_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	oauthprovider "github.com/BladiCreator/go-modular-auth/plugins/oauth-provider"
	"github.com/BladiCreator/go-modular-auth/plugins/oauth-provider/plugins"
)

func generatePKCEPair() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-abcdef123456789"
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

func setupProvider(t *testing.T) (oauthprovider.OAuthProvider, *auth.Auth) {
	t.Helper()
	mod := oauthprovider.New(
		oauthprovider.WithAccessTokenTTL(10*time.Minute),
		oauthprovider.WithAuthorizationCodeTTL(2*time.Minute),
		oauthprovider.WithRefreshTokenTTL(24*time.Hour),
		oauthprovider.WithRotateRefreshTokens(true),
	)

	engine, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to initialize auth engine: %v", err)
	}

	provider, err := auth.Get[plugins.OAuthProvider](engine)
	if err != nil {
		t.Fatalf("failed to resolve plugins.OAuthProvider capability: %v", err)
	}

	return provider, engine
}

func TestOAuthProvider_ClientRegistration(t *testing.T) {
	provider, _ := setupProvider(t)
	ctx := context.Background()

	// 1. Register Public Client (e.g. Single Page App)
	pubOut, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "SPA Dashboard",
		ClientType:        oauthprovider.ClientTypePublic,
		RedirectURIs:      []string{"https://app.example.com/callback"},
		AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode},
		AllowedScopes:     []string{"openid", "profile", "read:data"},
	})
	if err != nil {
		t.Fatalf("expected successful public client registration: %v", err)
	}
	if pubOut.Client.ID == "" {
		t.Errorf("expected non-empty client ID")
	}
	if pubOut.ClientSecret != "" {
		t.Errorf("public client must not receive a client secret")
	}
	if pubOut.Client.Status != oauthprovider.ClientStatusActive {
		t.Errorf("expected active client status, got %s", pubOut.Client.Status)
	}

	// 2. Register Confidential Client (e.g. Backend service)
	confOut, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "Backend Worker",
		ClientType:        oauthprovider.ClientTypeConfidential,
		RedirectURIs:      []string{"https://api.example.com/oauth/callback"},
		AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode, oauthprovider.GrantTypeClientCredentials, oauthprovider.GrantTypeRefreshToken},
		AllowedScopes:     []string{"admin", "write:data"},
	})
	if err != nil {
		t.Fatalf("expected successful confidential client registration: %v", err)
	}
	if confOut.ClientSecret == "" {
		t.Errorf("confidential client must receive a client secret")
	}

	// 3. Retrieve Client
	fetched, err := provider.GetClient(ctx, confOut.Client.ID)
	if err != nil {
		t.Fatalf("failed to get client by ID: %v", err)
	}
	if fetched.Name != "Backend Worker" {
		t.Errorf("expected client name 'Backend Worker', got %s", fetched.Name)
	}

	// 4. Invalid Registration Requests
	_, err = provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name: "", // missing name
	})
	if err != oauthprovider.ErrInvalidRequest {
		t.Errorf("expected ErrInvalidRequest for empty name, got %v", err)
	}

	_, err = provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:         "SPA",
		ClientType:   oauthprovider.ClientTypePublic,
		RedirectURIs: nil, // public client without redirect URI
	})
	if err != oauthprovider.ErrInvalidRequest {
		t.Errorf("expected ErrInvalidRequest for public client without redirect URI, got %v", err)
	}
}

func TestOAuthProvider_AuthorizationCodeGrant_Flow(t *testing.T) {
	provider, _ := setupProvider(t)
	ctx := context.Background()

	// Register confidential client
	reg, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "Test Web App",
		ClientType:        oauthprovider.ClientTypeConfidential,
		RedirectURIs:      []string{"https://app.test.com/oauth2/callback"},
		AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode, oauthprovider.GrantTypeRefreshToken},
		AllowedScopes:     []string{"read:profile", "write:profile"},
	})
	if err != nil {
		t.Fatalf("failed to register client: %v", err)
	}

	verifier, challenge := generatePKCEPair()

	// 1. Authorize Request
	authOut, err := provider.Authorize(ctx, oauthprovider.AuthorizeInput{
		ClientID:            reg.Client.ID,
		UserID:              "user_12345",
		RedirectURI:         "https://app.test.com/oauth2/callback",
		ResponseType:        "code",
		Scopes:              []string{"read:profile"},
		State:               "state_xyz789",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		UserConsent:         true,
	})
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	if authOut.Code == "" {
		t.Fatal("expected non-empty authorization code")
	}
	if authOut.State != "state_xyz789" {
		t.Errorf("expected state 'state_xyz789', got %s", authOut.State)
	}

	// 2. Token Exchange (Authorization Code Grant)
	tokOut, err := provider.Token(ctx, oauthprovider.TokenInput{
		GrantType:    oauthprovider.GrantTypeAuthorizationCode,
		ClientID:     reg.Client.ID,
		ClientSecret: reg.ClientSecret,
		Code:         authOut.Code,
		RedirectURI:  "https://app.test.com/oauth2/callback",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}
	if tokOut.AccessToken == "" || tokOut.RefreshToken == "" {
		t.Fatalf("expected both access token and refresh token to be issued")
	}
	if tokOut.TokenType != "Bearer" {
		t.Errorf("expected token_type 'Bearer', got %s", tokOut.TokenType)
	}

	// 3. Introspect Access Token
	intro, err := provider.IntrospectToken(ctx, oauthprovider.IntrospectTokenInput{
		Token:    tokOut.AccessToken,
		ClientID: reg.Client.ID,
	})
	if err != nil {
		t.Fatalf("introspection failed: %v", err)
	}
	if !intro.Active {
		t.Errorf("expected access token to be active")
	}
	if intro.Sub != "user_12345" {
		t.Errorf("expected subject 'user_12345', got %s", intro.Sub)
	}
	if intro.ClientID != reg.Client.ID {
		t.Errorf("expected client ID %s, got %s", reg.Client.ID, intro.ClientID)
	}

	// 4. Refresh Token Grant with Rotation
	oldRefreshToken := tokOut.RefreshToken
	refOut, err := provider.Token(ctx, oauthprovider.TokenInput{
		GrantType:    oauthprovider.GrantTypeRefreshToken,
		ClientID:     reg.Client.ID,
		ClientSecret: reg.ClientSecret,
		RefreshToken: oldRefreshToken,
	})
	if err != nil {
		t.Fatalf("refresh token grant failed: %v", err)
	}
	if refOut.AccessToken == "" || refOut.RefreshToken == "" {
		t.Fatalf("expected new access and rotated refresh token")
	}
	if refOut.RefreshToken == oldRefreshToken {
		t.Errorf("expected refresh token to be rotated, but got identical token")
	}

	// 5. Verify Old Refresh Token was Revoked by Rotation
	introOld, err := provider.IntrospectToken(ctx, oauthprovider.IntrospectTokenInput{
		Token:    oldRefreshToken,
		ClientID: reg.Client.ID,
	})
	if err != nil {
		t.Fatalf("failed to introspect old refresh token: %v", err)
	}
	if introOld.Active {
		t.Errorf("expected rotated old refresh token to be inactive")
	}

	// 6. Token Revocation (RFC 7009)
	err = provider.RevokeToken(ctx, oauthprovider.RevokeTokenInput{
		Token:    tokOut.AccessToken,
		ClientID: reg.Client.ID,
	})
	if err != nil {
		t.Fatalf("revoke token failed: %v", err)
	}

	introRevoked, err := provider.IntrospectToken(ctx, oauthprovider.IntrospectTokenInput{
		Token: tokOut.AccessToken,
	})
	if err != nil {
		t.Fatalf("introspection after revocation failed: %v", err)
	}
	if introRevoked.Active {
		t.Errorf("expected revoked access token to be inactive")
	}
}

func TestOAuthProvider_ClientCredentialsGrant_Flow(t *testing.T) {
	provider, _ := setupProvider(t)
	ctx := context.Background()

	reg, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "M2M Microservice",
		ClientType:        oauthprovider.ClientTypeConfidential,
		RedirectURIs:      nil,
		AllowedGrantTypes: []string{oauthprovider.GrantTypeClientCredentials},
		AllowedScopes:     []string{"service:read", "service:write"},
	})
	if err != nil {
		t.Fatalf("failed to register client: %v", err)
	}

	// 1. Successful Client Credentials Request
	tokOut, err := provider.Token(ctx, oauthprovider.TokenInput{
		GrantType:    oauthprovider.GrantTypeClientCredentials,
		ClientID:     reg.Client.ID,
		ClientSecret: reg.ClientSecret,
		Scopes:       []string{"service:read"},
	})
	if err != nil {
		t.Fatalf("client credentials token request failed: %v", err)
	}
	if tokOut.AccessToken == "" {
		t.Fatalf("expected non-empty access token")
	}
	if tokOut.RefreshToken != "" {
		t.Errorf("client credentials grant must NOT issue a refresh token")
	}

	// 2. Introspection
	intro, err := provider.IntrospectToken(ctx, oauthprovider.IntrospectTokenInput{
		Token: tokOut.AccessToken,
	})
	if err != nil {
		t.Fatalf("introspection failed: %v", err)
	}
	if !intro.Active {
		t.Errorf("expected active token")
	}
	if intro.Sub != reg.Client.ID {
		t.Errorf("expected subject to be client ID %s, got %s", reg.Client.ID, intro.Sub)
	}

	// 3. Invalid Secret
	_, err = provider.Token(ctx, oauthprovider.TokenInput{
		GrantType:    oauthprovider.GrantTypeClientCredentials,
		ClientID:     reg.Client.ID,
		ClientSecret: "wrong_secret_value",
	})
	if err != oauthprovider.ErrInvalidClient {
		t.Errorf("expected ErrInvalidClient for bad secret, got %v", err)
	}
}

func TestOAuthProvider_TypedCapabilityLookup(t *testing.T) {
	_, engine := setupProvider(t)

	// Verify lookup with plugins.OAuthProvider alias
	p1, err := auth.Get[plugins.OAuthProvider](engine)
	if err != nil || p1 == nil {
		t.Fatalf("failed to resolve auth.Get[plugins.OAuthProvider]: %v", err)
	}

	// Verify lookup with oauthprovider.OAuthProvider
	p2, err := auth.Get[oauthprovider.OAuthProvider](engine)
	if err != nil || p2 == nil {
		t.Fatalf("failed to resolve auth.Get[oauthprovider.OAuthProvider]: %v", err)
	}
}
