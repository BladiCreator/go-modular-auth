package username_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	memstore "github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth-username"
)

func TestPluginModuleRegistration(t *testing.T) {
	mod := username.New()
	if mod.ID() != "username" {
		t.Fatalf("expected module ID 'username', got %s", mod.ID())
	}

	a, err := auth.New(auth.Config{
		Store:   memstore.New(),
		Hasher:  fastHasher,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	// Verify typed lookup via username.Capability
	cap, err := a.Get[username.Capability]()
	if err != nil {
		t.Fatalf("a.Get[username.Capability]() failed: %v", err)
	}
	if cap == nil {
		t.Fatal("expected non-nil capability")
	}

	// Verify typed lookup via username.Username alias
	uCap, err := a.Get[username.Username]()
	if err != nil {
		t.Fatalf("a.Get[username.Username]() failed: %v", err)
	}
	if uCap == nil {
		t.Fatal("expected non-nil capability via alias")
	}
}

func TestCaseSensitiveConfiguration(t *testing.T) {
	ctx := context.Background()
	mod := username.New(
		username.WithCaseSensitive(true),
	)

	a, err := auth.New(auth.Config{
		Store:   memstore.New(),
		Hasher:  fastHasher,
		Plugins: []auth.PluginModule{mod},
	})
	if err != nil {
		t.Fatal(err)
	}

	cap, err := a.Get[username.Capability]()
	if err != nil {
		t.Fatal(err)
	}

	// Register Alice
	_, err = cap.Register(ctx, username.RegisterInput{
		Email:    "alice1@example.com",
		Username: "Alice",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatal(err)
	}

	// In case-sensitive mode, "alice" is considered a distinct username
	_, err = cap.Register(ctx, username.RegisterInput{
		Email:    "alice2@example.com",
		Username: "alice",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("expected distinct registration in case-sensitive mode, got: %v", err)
	}

	// Casing mismatch in authentication must fail
	_, err = cap.Authenticate(ctx, username.AuthenticateInput{
		Username: "ALICE",
		Password: "Password123!",
	})
	if !errors.Is(err, username.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for mismatched casing in case-sensitive mode, got: %v", err)
	}
}
