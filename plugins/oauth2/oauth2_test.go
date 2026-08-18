package oauth2_test

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/oauth2"
	"github.com/asaskevich/EventBus"
)

type mockCrypto struct{}

func (m *mockCrypto) HashPassword(p string) (string, error)   { return "hash:" + p, nil }
func (m *mockCrypto) ComparePassword(h, p string) bool        { return h == "hash:"+p }
func (m *mockCrypto) GenerateRandomToken(l int) (string, error) {
	return oauth2.GenerateRandomString(l)
}

func setupOAuth2Test(t *testing.T, opts ...oauth2.Option) (*oauth2.Plugin, *memory.Store, *entity.User, *oauth2.OAuthClient) {
	store := memory.New()
	bus := EventBus.New()
	pCtx := plugin.NewContext(&mockCrypto{}, bus)

	defaultOpts := []oauth2.Option{
		oauth2.WithIssuer("https://auth.example.com"),
		oauth2.WithPages("/sign-in", "/consent"),
		oauth2.WithAccessTokenType(oauth2.AccessTokenTypeJWT),
		oauth2.WithScopes("openid", "profile", "email", "offline_access", "phone"),
		oauth2.WithPairwiseSecret("test-pairwise-secret-key-32b-salt"),
		oauth2.WithStoreModes(oauth2.StoreModeHashed, oauth2.StoreModeHashed, "test-master-secret-key-32-bytes!"),
	}
	defaultOpts = append(defaultOpts, opts...)

	p := oauth2.New(store, defaultOpts...)
	if err := p.Init(pCtx); err != nil {
		t.Fatalf("failed to init oauth2 plugin: %v", err)
	}

	// Create test user
	user, err := store.CreateUser(context.Background(), &dto.CreateUserParams{
		Name:         "John Doe",
		Email:        "john@example.com",
		PasswordHash: "hash:secret123",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	user.EmailVerified = true
	phone := "+1234567890"
	user.PhoneNumber = &phone
	user.PhoneNumberVerified = true
	_ = store.UpdateUser(context.Background(), user)

	// Create test client
	clientSecret := "confidential-client-secret-1234"
	regRes, err := p.RegisterClient(context.Background(), oauth2.RegisterClientParams{
		ClientName:   "Test App",
		RedirectURIs: []string{"https://app.example.com/callback", "http://localhost:3000/callback"},
		GrantTypes:   []oauth2.GrantType{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken, oauth2.GrantTypeClientCredentials},
		Scope:        "openid profile email offline_access",
		Public:       false,
		SkipConsent:  false,
	})
	if err != nil {
		t.Fatalf("failed to register client: %v", err)
	}
	client := regRes.Client
	hashedSecret := oauth2.HashSecret(clientSecret)
	client.ClientSecret = &hashedSecret
	_ = store.UpdateClient(context.Background(), client)

	return p, store, user, client
}

func TestOAuth2_AuthorizationCodeFlow_FullCycle(t *testing.T) {
	p, store, user, client := setupOAuth2Test(t)
	ctx := context.Background()

	// 1. Generate PKCE verifier and S256 challenge
	verifier, err := oauth2.GenerateRandomString(32)
	if err != nil {
		t.Fatalf("failed to generate verifier: %v", err)
	}
	challenge := oauth2.ComputeCodeChallenge(verifier)

	// 2. Pre-consent user for testing
	_ = store.CreateConsent(ctx, &oauth2.OAuthConsent{
		ID:        "consent-1",
		ClientID:  client.ClientID,
		UserID:    user.ID,
		Scopes:    []string{"openid", "profile", "email", "offline_access"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	// 3. Authorize Request
	authRes, err := p.Authorize(ctx, oauth2.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Scope:               "openid profile email offline_access",
		State:               "state-xyz-123",
		Nonce:               "nonce-abc-456",
		UserID:              user.ID,
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	if authRes.Code == "" {
		t.Fatalf("expected authorization code to be issued")
	}
	if authRes.State != "state-xyz-123" {
		t.Errorf("expected state 'state-xyz-123', got '%s'", authRes.State)
	}
	if authRes.Issuer != "https://auth.example.com" {
		t.Errorf("expected iss 'https://auth.example.com', got '%s'", authRes.Issuer)
	}
	if !strings.Contains(authRes.RedirectURI, "iss=") {
		t.Errorf("expected RFC 9207 iss in callback URL, got %s", authRes.RedirectURI)
	}

	// 4. Exchange Code for Tokens at Token Endpoint
	tokenRes, err := p.Token(ctx, oauth2.TokenParams{
		GrantType:    "authorization_code",
		Code:         authRes.Code,
		CodeVerifier: verifier,
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
		RedirectURI:  "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}

	if tokenRes.AccessToken == "" {
		t.Fatalf("expected Access Token in response")
	}
	if tokenRes.RefreshToken == "" {
		t.Fatalf("expected Refresh Token in response (offline_access requested)")
	}
	if tokenRes.IDToken == "" {
		t.Fatalf("expected ID Token in response (openid requested)")
	}
	if tokenRes.TokenType != "Bearer" {
		t.Errorf("expected Bearer token type, got %s", tokenRes.TokenType)
	}

	// 5. Introspect Issued Access Token (RFC 7662)
	introRes, err := p.Introspect(ctx, oauth2.IntrospectParams{
		Token:        tokenRes.AccessToken,
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
	})
	if err != nil {
		t.Fatalf("Introspect failed: %v", err)
	}
	if !introRes.Active {
		t.Errorf("expected access token to be active")
	}
	if introRes.Sub != user.ID {
		t.Errorf("expected sub '%s', got '%s'", user.ID, introRes.Sub)
	}

	// 6. UserInfo Endpoint (OIDC Core 1.0)
	userInfoRes, err := p.UserInfo(ctx, oauth2.UserInfoParams{
		AccessToken: tokenRes.AccessToken,
	})
	if err != nil {
		t.Fatalf("UserInfo failed: %v", err)
	}
	if userInfoRes.Sub != user.ID {
		t.Errorf("expected userInfo sub '%s', got '%s'", user.ID, userInfoRes.Sub)
	}
	if userInfoRes.Email != user.Email {
		t.Errorf("expected userInfo email '%s', got '%s'", user.Email, userInfoRes.Email)
	}
	if userInfoRes.Name != user.Name {
		t.Errorf("expected userInfo name '%s', got '%s'", user.Name, userInfoRes.Name)
	}

	// 7. Refresh Token Exchange & Rotation
	refRes, err := p.Token(ctx, oauth2.TokenParams{
		GrantType:    "refresh_token",
		RefreshToken: tokenRes.RefreshToken,
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
	})
	if err != nil {
		t.Fatalf("Refresh Token exchange failed: %v", err)
	}
	if refRes.AccessToken == "" || refRes.RefreshToken == "" {
		t.Fatalf("expected new rotated tokens")
	}
	if refRes.RefreshToken == tokenRes.RefreshToken {
		t.Errorf("expected new refresh token to be rotated and distinct")
	}

	// 8. Re-attempting old Refresh Token MUST trigger theft detection and fail
	_, err = p.Token(ctx, oauth2.TokenParams{
		GrantType:    "refresh_token",
		RefreshToken: tokenRes.RefreshToken,
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
	})
	if err == nil {
		t.Fatalf("expected reusing old refresh token to fail with revocation")
	}
	if err != oauth2.ErrInvalidRefreshToken && err != oauth2.ErrRefreshTokenRevoked {
		t.Errorf("unexpected error on reuse: %v", err)
	}
}

func TestOAuth2_StrictPKCE_Validation(t *testing.T) {
	p, store, user, client := setupOAuth2Test(t)
	ctx := context.Background()

	_ = store.CreateConsent(ctx, &oauth2.OAuthConsent{
		ID:        "consent-pkce",
		ClientID:  client.ClientID,
		UserID:    user.ID,
		Scopes:    []string{"openid"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	verifier := "my-pkce-verifier-123456789012345678901234"
	challenge := oauth2.ComputeCodeChallenge(verifier)

	// Plain method must be rejected in OAuth 2.1
	_, err := p.Authorize(ctx, oauth2.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		CodeChallenge:       verifier,
		CodeChallengeMethod: "plain",
		Scope:               "openid",
		UserID:              user.ID,
	})
	if err != oauth2.ErrInvalidCodeChallengeMethod {
		t.Errorf("expected ErrInvalidCodeChallengeMethod for plain PKCE, got %v", err)
	}

	// Valid S256 Authorize
	authRes, err := p.Authorize(ctx, oauth2.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Scope:               "openid",
		UserID:              user.ID,
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	// Token exchange with wrong verifier must fail
	_, err = p.Token(ctx, oauth2.TokenParams{
		GrantType:    "authorization_code",
		Code:         authRes.Code,
		CodeVerifier: "wrong-verifier",
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
		RedirectURI:  "https://app.example.com/callback",
	})
	if err != oauth2.ErrInvalidPKCE {
		t.Errorf("expected ErrInvalidPKCE, got %v", err)
	}
}

func TestOAuth2_AtomicSingleUse_Concurrency(t *testing.T) {
	p, store, user, client := setupOAuth2Test(t)
	ctx := context.Background()

	_ = store.CreateConsent(ctx, &oauth2.OAuthConsent{
		ID:        "consent-atomic",
		ClientID:  client.ClientID,
		UserID:    user.ID,
		Scopes:    []string{"openid"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	verifier := "concurrent-verifier-12345678901234567890"
	challenge := oauth2.ComputeCodeChallenge(verifier)

	authRes, err := p.Authorize(ctx, oauth2.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Scope:               "openid",
		UserID:              user.ID,
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	// 20 concurrent goroutines attempting to consume the SAME code
	concurrency := 20
	var successCount int32
	var failCount int32
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Token(ctx, oauth2.TokenParams{
				GrantType:    "authorization_code",
				Code:         authRes.Code,
				CodeVerifier: verifier,
				ClientID:     client.ClientID,
				ClientSecret: "confidential-client-secret-1234",
				RedirectURI:  "https://app.example.com/callback",
			})
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			} else if err == oauth2.ErrInvalidAuthorizationCode {
				atomic.AddInt32(&failCount, 1)
			}
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful consumption, got %d", successCount)
	}
	if failCount != int32(concurrency-1) {
		t.Fatalf("expected %d failures with ErrInvalidAuthorizationCode, got %d", concurrency-1, failCount)
	}
}

func TestOAuth2_InteractiveRedirects_HMACSignatures(t *testing.T) {
	p, _, user, client := setupOAuth2Test(t)
	ctx := context.Background()

	verifier := "interactive-verifier-12345678901234567890"
	challenge := oauth2.ComputeCodeChallenge(verifier)

	// 1. Authorize without user authenticated -> Redirect to Login Page
	authRes, err := p.Authorize(ctx, oauth2.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Scope:               "openid profile",
		State:               "state-1",
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
	if !authRes.NeedsLogin {
		t.Errorf("expected NeedsLogin to be true")
	}

	// Parse redirect URL
	u, err := url.Parse(authRes.RedirectURI)
	if err != nil {
		t.Fatalf("failed to parse redirect url: %v", err)
	}
	q := u.Query()
	oauthQuery := q.Get("oauth_query")
	oauthSig := q.Get("oauth_signature")

	if oauthQuery == "" || oauthSig == "" {
		t.Fatalf("expected oauth_query and oauth_signature in redirect")
	}

	// 2. Tampered signature must fail ContinueAuthorize
	_, err = p.ContinueAuthorize(ctx, oauth2.ContinueAuthorizeParams{
		OAuthQuery:     oauthQuery,
		OAuthSignature: "invalid-tampered-signature",
		UserID:         user.ID,
	})
	if err != oauth2.ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}

	// 3. Valid ContinueAuthorize -> Redirect to Consent Page (since consent not pre-granted)
	contRes, err := p.ContinueAuthorize(ctx, oauth2.ContinueAuthorizeParams{
		OAuthQuery:     oauthQuery,
		OAuthSignature: oauthSig,
		UserID:         user.ID,
	})
	if err != nil {
		t.Fatalf("ContinueAuthorize failed: %v", err)
	}
	if !contRes.NeedsConsent {
		t.Errorf("expected NeedsConsent to be true")
	}

	// 4. Process User Consent Approval
	uConsent, _ := url.Parse(contRes.RedirectURI)
	consentQ := uConsent.Query()
	consentRes, err := p.Consent(ctx, oauth2.ConsentParams{
		OAuthQuery:     consentQ.Get("oauth_query"),
		OAuthSignature: consentQ.Get("oauth_signature"),
		UserID:         user.ID,
		ApprovedScopes: []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("Consent failed: %v", err)
	}
	if consentRes.Code == "" {
		t.Fatalf("expected code after consent approval")
	}
}

func TestOAuth2_PairwiseSubject(t *testing.T) {
	p, store, user, _ := setupOAuth2Test(t)
	ctx := context.Background()

	// Register Pairwise Client
	regRes, err := p.RegisterClient(ctx, oauth2.RegisterClientParams{
		ClientName:   "Pairwise App",
		RedirectURIs: []string{"https://pairwise.example.com/callback"},
		Scope:        "openid",
		Public:       true,
		SubjectType:  oauth2.SubjectTypePairwise,
		SkipConsent:  true,
	})
	if err != nil {
		t.Fatalf("failed to register pairwise client: %v", err)
	}
	client := regRes.Client

	verifier := "pairwise-verifier-12345678901234567890"
	challenge := oauth2.ComputeCodeChallenge(verifier)

	authRes, err := p.Authorize(ctx, oauth2.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://pairwise.example.com/callback",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Scope:               "openid",
		UserID:              user.ID,
	})
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	tokenRes, err := p.Token(ctx, oauth2.TokenParams{
		GrantType:    "authorization_code",
		Code:         authRes.Code,
		CodeVerifier: verifier,
		ClientID:     client.ClientID,
		RedirectURI:  "https://pairwise.example.com/callback",
	})
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}

	userInfo, err := p.UserInfo(ctx, oauth2.UserInfoParams{
		AccessToken: tokenRes.AccessToken,
	})
	if err != nil {
		t.Fatalf("UserInfo failed: %v", err)
	}

	// Pairwise sub must NOT equal the real user ID
	if userInfo.Sub == user.ID {
		t.Errorf("expected pseudonymous pairwise sub, but got plain user.ID")
	}
	expectedPairwiseSub := oauth2.DerivePairwiseSubject("test-pairwise-secret-key-32b-salt", "https://pairwise.example.com/callback", user.ID)
	if userInfo.Sub != expectedPairwiseSub {
		t.Errorf("expected pairwise sub '%s', got '%s'", expectedPairwiseSub, userInfo.Sub)
	}
	_ = store
}

func TestOAuth2_ClientCredentials_M2M(t *testing.T) {
	p, _, _, client := setupOAuth2Test(t)
	ctx := context.Background()

	tokenRes, err := p.Token(ctx, oauth2.TokenParams{
		GrantType:    "client_credentials",
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
		Scope:        "openid",
	})
	if err != nil {
		t.Fatalf("client_credentials exchange failed: %v", err)
	}

	if tokenRes.AccessToken == "" {
		t.Fatalf("expected M2M access token")
	}
	if tokenRes.RefreshToken != "" {
		t.Errorf("client_credentials must NOT issue refresh token")
	}

	introRes, err := p.Introspect(ctx, oauth2.IntrospectParams{
		Token:        tokenRes.AccessToken,
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
	})
	if err != nil {
		t.Fatalf("Introspect failed: %v", err)
	}
	if !introRes.Active {
		t.Errorf("expected token to be active")
	}
	if introRes.ClientID != client.ClientID {
		t.Errorf("expected client_id '%s', got '%s'", client.ClientID, introRes.ClientID)
	}
}

func TestOAuth2_Revocation_RFC7009(t *testing.T) {
	p, store, user, client := setupOAuth2Test(t)
	ctx := context.Background()

	_ = store.CreateConsent(ctx, &oauth2.OAuthConsent{
		ID:        "consent-revoke",
		ClientID:  client.ClientID,
		UserID:    user.ID,
		Scopes:    []string{"openid", "offline_access"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	verifier := "revoke-verifier-1234567890123456789012"
	challenge := oauth2.ComputeCodeChallenge(verifier)

	authRes, _ := p.Authorize(ctx, oauth2.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         "https://app.example.com/callback",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Scope:               "openid offline_access",
		UserID:              user.ID,
	})

	tokenRes, _ := p.Token(ctx, oauth2.TokenParams{
		GrantType:    "authorization_code",
		Code:         authRes.Code,
		CodeVerifier: verifier,
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
		RedirectURI:  "https://app.example.com/callback",
	})

	// Revoke Access Token
	revRes, err := p.Revoke(ctx, oauth2.RevokeParams{
		Token:        tokenRes.AccessToken,
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
	})
	if err != nil || !revRes.Success {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Introspect must report inactive
	intro, _ := p.Introspect(ctx, oauth2.IntrospectParams{
		Token:        tokenRes.AccessToken,
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
	})
	if intro.Active {
		t.Errorf("expected revoked token to be inactive")
	}
}

func TestOAuth2_DiscoveryMetadata(t *testing.T) {
	p, _, _, _ := setupOAuth2Test(t)
	ctx := context.Background()

	oidcMeta, err := p.GetOpenIDConfiguration(ctx, oauth2.OpenIDConfigurationParams{})
	if err != nil {
		t.Fatalf("GetOpenIDConfiguration failed: %v", err)
	}
	if oidcMeta.Issuer != "https://auth.example.com" {
		t.Errorf("expected issuer 'https://auth.example.com', got '%s'", oidcMeta.Issuer)
	}
	if !containsStr(oidcMeta.CodeChallengeMethodsSupported, "S256") {
		t.Errorf("expected S256 code challenge method supported")
	}

	oauthMeta, err := p.GetOAuthAuthorizationServerMetadata(ctx, oauth2.OAuthMetadataParams{})
	if err != nil {
		t.Fatalf("GetOAuthAuthorizationServerMetadata failed: %v", err)
	}
	if oauthMeta.Issuer != "https://auth.example.com" {
		t.Errorf("expected issuer 'https://auth.example.com', got '%s'", oauthMeta.Issuer)
	}
}

func TestOAuth2_EndSession_RPInitiatedLogout(t *testing.T) {
	p, store, user, client := setupOAuth2Test(t)
	ctx := context.Background()

	client.EnableEndSession = true
	client.PostLogoutRedirectURIs = []string{"https://app.example.com/post-logout"}
	_ = store.UpdateClient(ctx, client)

	sessionID := "active-session-123"
	now := time.Now()
	store.SaveSession(&entity.Session{
		ID:        sessionID,
		UserID:    user.ID,
		Token:     "session-token-abc",
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
		UpdatedAt: &now,
	})

	endRes, err := p.EndSession(ctx, oauth2.EndSessionParams{
		ClientID:              client.ClientID,
		SessionID:             sessionID,
		PostLogoutRedirectURI: "https://app.example.com/post-logout",
		State:                 "logout-state-999",
	})
	if err != nil {
		t.Fatalf("EndSession failed: %v", err)
	}

	if !strings.Contains(endRes.RedirectURI, "logout-state-999") {
		t.Errorf("expected state in post-logout redirect uri, got %s", endRes.RedirectURI)
	}

	// Session should be terminated
	_, err = store.FindSessionByID(ctx, sessionID)
	if err == nil {
		t.Errorf("expected session to be deleted upon logout")
	}
}

func containsStr(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
