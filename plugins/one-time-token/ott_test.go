package ott_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	ott "github.com/BladiCreator/go-modular-auth-one-time-token"
)

func setupTest(t *testing.T, opts ...ott.Option) (*auth.Auth, ott.OneTimeToken) {
	t.Helper()
	ad := adaptermem.New()
	mod := ott.New(append([]ott.Option{ott.WithTTL(5 * time.Minute)}, opts...)...)

	a, err := auth.New(auth.Config{
		Adapter: ad,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	svc, err := auth.Get[ott.OneTimeToken](a)
	if err != nil {
		t.Fatalf("failed to retrieve OneTimeToken capability: %v", err)
	}

	return a, svc
}

func TestOneTimeToken_Lifecycle(t *testing.T) {
	ctx := context.Background()
	_, svc := setupTest(t)

	// 1. Generate token
	token, err := svc.Generate(ctx, "user-123")
	if err != nil {
		t.Fatalf("expected no error on generate, got: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// 2. Consume token (first time - success)
	vt, err := svc.Consume(ctx, token)
	if err != nil {
		t.Fatalf("expected successful consume, got: %v", err)
	}
	if vt.Subject != "user-123" {
		t.Errorf("expected subject user-123, got: %s", vt.Subject)
	}

	// 3. Consume token again (must fail - single-use)
	_, err = svc.Consume(ctx, token)
	if err == nil {
		t.Fatal("expected error on re-consuming token, got nil")
	}

	// 4. Revocation
	token2, err := svc.Generate(ctx, "user-456")
	if err != nil {
		t.Fatalf("failed to generate second token: %v", err)
	}
	if err := svc.Revoke(ctx, "user-456"); err != nil {
		t.Fatalf("failed to revoke tokens: %v", err)
	}
	_, err = svc.Consume(ctx, token2)
	if err == nil {
		t.Fatal("expected error consuming revoked token, got nil")
	}
}
