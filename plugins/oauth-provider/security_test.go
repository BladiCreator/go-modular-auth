package oauthprovider_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	oauthprovider "github.com/BladiCreator/go-modular-auth/plugins/oauth-provider"
)

func TestSecurity_PKCE_Enforcement(t *testing.T) {
	provider, _ := setupProvider(t)
	ctx := context.Background()

	// Register public client (SPA)
	reg, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "Public Web App",
		ClientType:        oauthprovider.ClientTypePublic,
		RedirectURIs:      []string{"https://spa.example.com/oauth/callback"},
		AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("failed to register public client: %v", err)
	}

	verifier, challenge := generatePKCEPair()

	// 1. Authorize without PKCE challenge must fail for public client
	_, err = provider.Authorize(ctx, oauthprovider.AuthorizeInput{
		ClientID:     reg.Client.ID,
		UserID:       "user_999",
		RedirectURI:  "https://spa.example.com/oauth/callback",
		ResponseType: "code",
		UserConsent:  true,
		// Missing CodeChallenge & CodeChallengeMethod
	})
	if err != oauthprovider.ErrPKCERequired {
		t.Errorf("expected ErrPKCERequired for public client without PKCE, got %v", err)
	}

	// 2. Authorize with 'plain' challenge method must fail under OAuth 2.1
	_, err = provider.Authorize(ctx, oauthprovider.AuthorizeInput{
		ClientID:            reg.Client.ID,
		UserID:              "user_999",
		RedirectURI:         "https://spa.example.com/oauth/callback",
		ResponseType:        "code",
		CodeChallenge:       verifier,
		CodeChallengeMethod: "plain",
		UserConsent:         true,
	})
	if err != oauthprovider.ErrInvalidPKCE {
		t.Errorf("expected ErrInvalidPKCE for 'plain' PKCE method, got %v", err)
	}

	// 3. Issue valid code with S256
	authOut, err := provider.Authorize(ctx, oauthprovider.AuthorizeInput{
		ClientID:            reg.Client.ID,
		UserID:              "user_999",
		RedirectURI:         "https://spa.example.com/oauth/callback",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		UserConsent:         true,
	})
	if err != nil {
		t.Fatalf("failed to authorize with S256 PKCE: %v", err)
	}

	// 4. Token request with mismatched code_verifier must fail
	_, err = provider.Token(ctx, oauthprovider.TokenInput{
		GrantType:    oauthprovider.GrantTypeAuthorizationCode,
		ClientID:     reg.Client.ID,
		Code:         authOut.Code,
		RedirectURI:  "https://spa.example.com/oauth/callback",
		CodeVerifier: "wrong_verifier_abcdefghijklmnopqrstuvwxyz012345",
	})
	if err != oauthprovider.ErrInvalidPKCE {
		t.Errorf("expected ErrInvalidPKCE for incorrect code verifier, got %v", err)
	}
}

func TestSecurity_ExactRedirectURIMatching(t *testing.T) {
	provider, _ := setupProvider(t)
	ctx := context.Background()

	reg, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "Secure Client",
		ClientType:        oauthprovider.ClientTypePublic,
		RedirectURIs:      []string{"https://example.com/auth/callback"},
		AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, challenge := generatePKCEPair()

	invalidURIs := []string{
		"https://example.com/auth/callback/",          // trailing slash
		"https://example.com/auth/callback?extra=foo", // query parameter
		"https://sub.example.com/auth/callback",       // subdomain mismatch
		"http://example.com/auth/callback",            // insecure protocol
		"https://example.com/auth",                    // truncated path
	}

	for _, uri := range invalidURIs {
		_, err := provider.Authorize(ctx, oauthprovider.AuthorizeInput{
			ClientID:            reg.Client.ID,
			UserID:              "user_1",
			RedirectURI:         uri,
			ResponseType:        "code",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
			UserConsent:         true,
		})
		if err != oauthprovider.ErrRedirectURIMismatch {
			t.Errorf("expected ErrRedirectURIMismatch for %q, got %v", uri, err)
		}
	}
}

func TestSecurity_SingleUseAuthorizationCode_AntiReplay(t *testing.T) {
	provider, _ := setupProvider(t)
	ctx := context.Background()

	reg, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "Confidential App",
		ClientType:        oauthprovider.ClientTypeConfidential,
		RedirectURIs:      []string{"https://app.example.com/cb"},
		AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	verifier, challenge := generatePKCEPair()

	authOut, err := provider.Authorize(ctx, oauthprovider.AuthorizeInput{
		ClientID:            reg.Client.ID,
		UserID:              "user_100",
		RedirectURI:         "https://app.example.com/cb",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		UserConsent:         true,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	// First redemption must succeed
	tokOut, err := provider.Token(ctx, oauthprovider.TokenInput{
		GrantType:    oauthprovider.GrantTypeAuthorizationCode,
		ClientID:     reg.Client.ID,
		ClientSecret: reg.ClientSecret,
		Code:         authOut.Code,
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("first token exchange failed: %v", err)
	}
	if tokOut.AccessToken == "" {
		t.Fatal("expected access token on first redemption")
	}

	// Second redemption (replay attempt) must fail with ErrInvalidGrant
	_, err = provider.Token(ctx, oauthprovider.TokenInput{
		GrantType:    oauthprovider.GrantTypeAuthorizationCode,
		ClientID:     reg.Client.ID,
		ClientSecret: reg.ClientSecret,
		Code:         authOut.Code,
		RedirectURI:  "https://app.example.com/cb",
		CodeVerifier: verifier,
	})
	if err != oauthprovider.ErrInvalidGrant {
		t.Errorf("expected ErrInvalidGrant on code replay, got %v", err)
	}
}

func TestSecurity_ConcurrentCodeConsumption(t *testing.T) {
	provider, _ := setupProvider(t)
	ctx := context.Background()

	reg, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "Concurrent Client",
		ClientType:        oauthprovider.ClientTypeConfidential,
		RedirectURIs:      []string{"https://concurrent.example.com/cb"},
		AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	verifier, challenge := generatePKCEPair()

	authOut, err := provider.Authorize(ctx, oauthprovider.AuthorizeInput{
		ClientID:            reg.Client.ID,
		UserID:              "user_race",
		RedirectURI:         "https://concurrent.example.com/cb",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		UserConsent:         true,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	// 10 concurrent redemption goroutines attempting to consume the same code
	concurrency := 10
	var wg sync.WaitGroup
	var successCount int64

	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			_, err := provider.Token(ctx, oauthprovider.TokenInput{
				GrantType:    oauthprovider.GrantTypeAuthorizationCode,
				ClientID:     reg.Client.ID,
				ClientSecret: reg.ClientSecret,
				Code:         authOut.Code,
				RedirectURI:  "https://concurrent.example.com/cb",
				CodeVerifier: verifier,
			})
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful consumption among concurrent workers, got %d", successCount)
	}
}

func TestSecurity_ClientRevocation(t *testing.T) {
	provider, _ := setupProvider(t)
	ctx := context.Background()

	reg, err := provider.RegisterClient(ctx, oauthprovider.RegisterClientInput{
		Name:              "Revocable Client",
		ClientType:        oauthprovider.ClientTypeConfidential,
		RedirectURIs:      []string{"https://app.test.com/cb"},
		AllowedGrantTypes: []string{oauthprovider.GrantTypeAuthorizationCode, oauthprovider.GrantTypeClientCredentials},
	})
	if err != nil {
		t.Fatalf("client registration failed: %v", err)
	}

	// Revoke the client
	err = provider.RevokeClient(ctx, reg.Client.ID)
	if err != nil {
		t.Fatalf("revoke client failed: %v", err)
	}

	// Authorize must fail with ErrClientRevoked
	_, challenge := generatePKCEPair()
	_, err = provider.Authorize(ctx, oauthprovider.AuthorizeInput{
		ClientID:            reg.Client.ID,
		UserID:              "user_revoked",
		RedirectURI:         "https://app.test.com/cb",
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		UserConsent:         true,
	})
	if err != oauthprovider.ErrClientRevoked {
		t.Errorf("expected ErrClientRevoked on authorize, got %v", err)
	}

	// Client credentials grant must fail with ErrClientRevoked
	_, err = provider.Token(ctx, oauthprovider.TokenInput{
		GrantType:    oauthprovider.GrantTypeClientCredentials,
		ClientID:     reg.Client.ID,
		ClientSecret: reg.ClientSecret,
	})
	if err != oauthprovider.ErrClientRevoked {
		t.Errorf("expected ErrClientRevoked on token request, got %v", err)
	}
}
