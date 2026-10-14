package oidcprovider_test

import (
	"context"
	"strings"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	"github.com/BladiCreator/go-modular-auth/user"
	oidcprovider "github.com/BladiCreator/go-modular-auth-oidc-provider"
)

func TestOIDCProvider_DiscoveryAndTokens(t *testing.T) {
	ctx := context.Background()
	mod := oidcprovider.New(oidcprovider.WithIssuer("https://auth.example.com"))

	ad := adaptermem.New()
	a, err := auth.New(auth.Config{
		Adapter: ad,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	testUser := &user.User{
		ID:            "u-123",
		Email:         "test@example.com",
		EmailVerified: true,
	}
	if err := a.Store().Users().Create(ctx, testUser); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	provider, err := auth.Get[oidcprovider.OIDCProvider](a)
	if err != nil {
		t.Fatalf("failed to get OIDCProvider: %v", err)
	}

	// 1. Discovery
	disc := provider.GetDiscovery()
	if disc.Issuer != "https://auth.example.com" {
		t.Errorf("expected issuer https://auth.example.com, got: %s", disc.Issuer)
	}
	if disc.JwksURI != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("unexpected jwks_uri: %s", disc.JwksURI)
	}

	// 2. JWKS
	jwksResp, err := provider.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("failed to get JWKS: %v", err)
	}
	if len(jwksResp.Keys) == 0 {
		t.Fatal("expected at least one JWK key")
	}
	if jwksResp.Keys[0].Kty != "RSA" {
		t.Errorf("expected RSA key type, got: %s", jwksResp.Keys[0].Kty)
	}

	// 3. Issue ID Token
	token, err := provider.IssueIDToken(ctx, testUser, "client-app-1", "nonce-xyz", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue ID token: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}

	// 4. UserInfo
	userInfo, err := provider.GetUserInfo(ctx, testUser.ID)
	if err != nil {
		t.Fatalf("failed to get user info: %v", err)
	}
	if userInfo["sub"] != "u-123" || userInfo["email"] != "test@example.com" {
		t.Errorf("unexpected user info claims: %+v", userInfo)
	}
}
