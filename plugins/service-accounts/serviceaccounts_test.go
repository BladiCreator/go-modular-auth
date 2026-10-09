package serviceaccounts_test

import (
	"context"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	storememory "github.com/BladiCreator/go-modular-auth/store/memory"
	serviceaccounts "github.com/BladiCreator/go-modular-auth-service-accounts"
)

func TestServiceAccounts_Lifecycle(t *testing.T) {
	ctx := context.Background()
	mod := serviceaccounts.New()

	a, err := auth.New(auth.Config{
		Store:   storememory.New(),
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("failed to create auth engine: %v", err)
	}

	mgr, err := auth.Get[serviceaccounts.ServiceAccountManager](a)
	if err != nil {
		t.Fatalf("failed to get ServiceAccountManager: %v", err)
	}

	// 1. Create service account
	sa, secret, err := mgr.Create(ctx, serviceaccounts.CreateInput{
		Name:        "CI/CD Pipeline",
		Description: "GitHub Actions Deployer",
		OwnerID:     "org-1",
		Scopes:      []string{"deploy:prod"},
	})
	if err != nil {
		t.Fatalf("failed to create service account: %v", err)
	}
	if sa.ID == "" || secret == "" {
		t.Fatalf("expected ID and secret, got id=%s secret=%s", sa.ID, secret)
	}

	// 2. Authenticate with valid secret
	authed, err := mgr.Authenticate(ctx, sa.ID, secret)
	if err != nil {
		t.Fatalf("expected successful auth: %v", err)
	}
	if authed.ID != sa.ID {
		t.Errorf("expected ID %s, got %s", sa.ID, authed.ID)
	}

	// 3. Authenticate with invalid secret
	_, err = mgr.Authenticate(ctx, sa.ID, "wrong-secret")
	if err != serviceaccounts.ErrInvalidSecret {
		t.Fatalf("expected ErrInvalidSecret, got: %v", err)
	}

	// 4. Rotate secret
	newSecret, err := mgr.RotateSecret(ctx, sa.ID)
	if err != nil {
		t.Fatalf("failed to rotate secret: %v", err)
	}
	if newSecret == secret {
		t.Fatal("expected new secret to differ from old secret")
	}

	// Old secret fails
	_, err = mgr.Authenticate(ctx, sa.ID, secret)
	if err != serviceaccounts.ErrInvalidSecret {
		t.Fatalf("expected old secret to fail after rotation: %v", err)
	}

	// New secret succeeds
	authed2, err := mgr.Authenticate(ctx, sa.ID, newSecret)
	if err != nil {
		t.Fatalf("expected successful auth with new secret: %v", err)
	}
	if authed2.ID != sa.ID {
		t.Errorf("mismatched id: %s", authed2.ID)
	}

	// 5. Revoke
	if err := mgr.Revoke(ctx, sa.ID); err != nil {
		t.Fatalf("failed to revoke service account: %v", err)
	}
	_, err = mgr.Authenticate(ctx, sa.ID, newSecret)
	if err != serviceaccounts.ErrInactive {
		t.Fatalf("expected ErrInactive after revoke, got: %v", err)
	}
}
