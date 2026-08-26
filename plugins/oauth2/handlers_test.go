package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugins/oauth2"
)

func TestOAuth2HTTPMiddleware(t *testing.T) {
	p, store, user, client := setupOAuth2Test(t)

	verifier, _ := oauth2.GenerateRandomString(32)
	challenge := oauth2.ComputeCodeChallenge(verifier)

	_ = store.CreateConsent(context.Background(), &oauth2.OAuthConsent{
		ID:        "consent-1",
		ClientID:  client.ClientID,
		UserID:    user.ID,
		Scopes:    []string{"openid", "profile", "email"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	// Create valid auth code & token
	authRes, err := p.Authorize(context.Background(), oauth2.AuthorizeParams{
		ClientID:            client.ClientID,
		RedirectURI:         client.RedirectURIs[0],
		ResponseType:        "code",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Scope:               "openid profile",
		UserID:              user.ID,
	})
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}

	tokRes, err := p.Token(context.Background(), oauth2.TokenParams{
		GrantType:    "authorization_code",
		Code:         authRes.Code,
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ClientID,
		ClientSecret: "confidential-client-secret-1234",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	handler := p.RequireScope("openid")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		intro, ok := r.Context().Value(oauth2.TokenIntrospectContextKey).(*oauth2.IntrospectResult)
		if !ok || intro == nil || !intro.Active {
			t.Errorf("expected active token introspect result")
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("missing authorization header returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d", rec.Code)
		}
	})

	t.Run("valid access token header passes middleware", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tokRes.AccessToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})
}
