package apikeys_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	apikeys "github.com/BladiCreator/go-modular-auth-apikeys"
	"github.com/BladiCreator/go-modular-auth-apikeys/plugins"
	"github.com/BladiCreator/go-modular-auth-apikeys/store/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	corestore "github.com/BladiCreator/go-modular-auth/store/memory"
)

func setupTestAuth(t *testing.T, opts ...apikeys.Option) (*auth.Auth, plugins.APIKeys, *memory.Store) {
	t.Helper()
	memStore := memory.New()
	memCache := corecache.New()

	defaultOpts := []apikeys.Option{
		apikeys.WithStore(memStore),
		apikeys.WithTouchLastUsedThreshold(10 * time.Millisecond),
	}
	allOpts := append(defaultOpts, opts...)

	engine, err := auth.New(auth.Config{
		Store: corestore.New(),
		Cache: memCache,
		Plugins: []auth.PluginModule{
			apikeys.New(allOpts...),
		},
	})
	if err != nil {
		t.Fatalf("failed to initialize GoModularAuth core: %v", err)
	}

	cap, err := auth.Get[plugins.APIKeys](engine)
	if err != nil {
		t.Fatalf("failed to retrieve APIKeys capability: %v", err)
	}

	return engine, cap, memStore
}

func TestAPIKeys_CreateAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	_, apiKeys, _ := setupTestAuth(t)

	// 1. Create key
	res, err := apiKeys.Create(ctx, apikeys.CreateInput{
		Name:           "Service CLI",
		UserID:         "user_123",
		OrganizationID: "org_456",
		Scopes:         []string{"read:users", "write:users"},
		Permissions:    []string{"users.manage"},
		Metadata:       map[string]string{"env": "production"},
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if !strings.HasPrefix(res.RawKey, "gma_") {
		t.Fatalf("expected raw key to start with 'gma_', got %s", res.RawKey)
	}
	if res.Key.ID == "" || res.Key.KeyHash == "" {
		t.Fatalf("missing ID or KeyHash in persisted key: %+v", res.Key)
	}
	if strings.Contains(res.Key.KeyHash, res.RawKey) {
		t.Fatalf("security violation: raw key found inside hash representation")
	}

	// 2. Authenticate with valid raw key
	authRes, err := apiKeys.Authenticate(ctx, res.RawKey,
		apikeys.WithIPAddress("192.168.1.10"),
		apikeys.WithUserAgent("test-agent/1.0"),
		apikeys.WithRequiredScopes("read:users"),
		apikeys.WithRequiredPermissions("users.manage"),
	)
	if err != nil {
		t.Fatalf("Authenticate failed with valid key: %v", err)
	}

	if authRes.Principal.Type != auth.PrincipalAPIKey {
		t.Errorf("expected principal type PrincipalAPIKey, got %s", authRes.Principal.Type)
	}
	if authRes.Principal.Subject != res.Key.ID {
		t.Errorf("expected principal subject %s, got %s", res.Key.ID, authRes.Principal.Subject)
	}
	if authRes.Key.LastUsedIP != "192.168.1.10" {
		t.Errorf("expected LastUsedIP to be recorded, got %s", authRes.Key.LastUsedIP)
	}

	// Context attachment helper verification
	ctxWithKey := apikeys.WithAPIKey(ctx, authRes.Key)
	retrievedKey, ok := apikeys.APIKeyFrom(ctxWithKey)
	if !ok || retrievedKey.ID != res.Key.ID {
		t.Fatalf("APIKeyFrom context failed to retrieve attached key")
	}

	// 3. Authenticate with invalid raw key
	_, err = apiKeys.Authenticate(ctx, "gma_invalid_fake_token")
	if !errors.Is(err, apikeys.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}

	// 4. Authenticate with insufficient scope
	_, err = apiKeys.Authenticate(ctx, res.RawKey, apikeys.WithRequiredScopes("billing:admin"))
	if !errors.Is(err, apikeys.ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}

	// 5. Authenticate with insufficient permission
	_, err = apiKeys.Authenticate(ctx, res.RawKey, apikeys.WithRequiredPermissions("superadmin"))
	if !errors.Is(err, apikeys.ErrInsufficientPermission) {
		t.Fatalf("expected ErrInsufficientPermission, got %v", err)
	}
}

func TestAPIKeys_OwnerSubjectStrategy(t *testing.T) {
	ctx := context.Background()
	_, apiKeys, _ := setupTestAuth(t, apikeys.WithSubjectStrategy(apikeys.SubjectStrategyOwner))

	res, err := apiKeys.Create(ctx, apikeys.CreateInput{
		Name:   "User Key",
		UserID: "usr_alice",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	authRes, err := apiKeys.Authenticate(ctx, res.RawKey)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if authRes.Principal.Subject != "usr_alice" {
		t.Fatalf("expected Subject to resolve to UserID usr_alice, got %s", authRes.Principal.Subject)
	}
}

func TestAPIKeys_Expiration(t *testing.T) {
	ctx := context.Background()
	_, apiKeys, _ := setupTestAuth(t)

	res, err := apiKeys.Create(ctx, apikeys.CreateInput{
		Name:      "Ephemeral Key",
		ExpiresIn: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Works before expiration
	if _, err := apiKeys.Authenticate(ctx, res.RawKey); err != nil {
		t.Fatalf("Authenticate before expiration failed: %v", err)
	}

	// Wait past expiration
	time.Sleep(70 * time.Millisecond)

	_, err = apiKeys.Authenticate(ctx, res.RawKey)
	if !errors.Is(err, apikeys.ErrKeyExpired) {
		t.Fatalf("expected ErrKeyExpired, got %v", err)
	}
}

func TestAPIKeys_RevocationAndCacheInvalidation(t *testing.T) {
	ctx := context.Background()
	_, apiKeys, _ := setupTestAuth(t)

	res, err := apiKeys.Create(ctx, apikeys.CreateInput{Name: "To Revoke"})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Warm cache
	if _, err := apiKeys.Authenticate(ctx, res.RawKey); err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// Revoke
	if err := apiKeys.Revoke(ctx, res.Key.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Immediate next authentication must fail even if previously cached
	_, err = apiKeys.Authenticate(ctx, res.RawKey)
	if !errors.Is(err, apikeys.ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked immediately after revocation, got %v", err)
	}
}

func TestAPIKeys_Rotation(t *testing.T) {
	ctx := context.Background()
	_, apiKeys, _ := setupTestAuth(t)

	// Create initial key
	res, err := apiKeys.Create(ctx, apikeys.CreateInput{
		Name:        "Old Service",
		UserID:      "u1",
		Scopes:      []string{"service:read"},
		Permissions: []string{"read"},
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Case 1: Immediate rotation (default)
	rotRes, err := apiKeys.Rotate(ctx, res.Key.ID)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// Old key should be revoked immediately
	_, err = apiKeys.Authenticate(ctx, res.RawKey)
	if !errors.Is(err, apikeys.ErrKeyRevoked) {
		t.Fatalf("expected old key to be revoked immediately, got %v", err)
	}

	// New key should succeed
	authRes, err := apiKeys.Authenticate(ctx, rotRes.RawKey)
	if err != nil {
		t.Fatalf("Authenticate with new rotated key failed: %v", err)
	}
	if authRes.Key.ID != rotRes.NewKey.ID {
		t.Errorf("expected new key ID, got %s", authRes.Key.ID)
	}

	// Case 2: Rotation with grace period
	rotRes2, err := apiKeys.Rotate(ctx, rotRes.NewKey.ID, apikeys.WithGracePeriod(100*time.Millisecond))
	if err != nil {
		t.Fatalf("Rotate with grace period failed: %v", err)
	}

	// Both keys should work during grace period
	if _, err := apiKeys.Authenticate(ctx, rotRes.RawKey); err != nil {
		t.Fatalf("old key within grace period should succeed, got %v", err)
	}
	if _, err := apiKeys.Authenticate(ctx, rotRes2.RawKey); err != nil {
		t.Fatalf("new key should succeed, got %v", err)
	}
}

func TestAPIKeys_EventsAndHooks(t *testing.T) {
	ctx := context.Background()
	engine, apiKeys, _ := setupTestAuth(t)

	var (
		mu             sync.Mutex
		eventsReceived []auth.EventName
		hookCreateRan  bool
		hookAuthRan    bool
		hookRevokeRan  bool
	)

	engine.Events().SubscribeAll(func(ctx context.Context, e auth.Event) {
		mu.Lock()
		eventsReceived = append(eventsReceived, e.Name)
		mu.Unlock()
	})

	apiKeys.Hooks().AfterCreate(func(ctx context.Context, key *apikeys.APIKey) {
		hookCreateRan = true
	})
	apiKeys.Hooks().AfterAuthenticate(func(ctx context.Context, res *apikeys.AuthResult) {
		hookAuthRan = true
	})
	apiKeys.Hooks().AfterRevoke(func(ctx context.Context, key *apikeys.APIKey) {
		hookRevokeRan = true
	})

	res, err := apiKeys.Create(ctx, apikeys.CreateInput{Name: "Observed Key"})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	_, _ = apiKeys.Authenticate(ctx, res.RawKey)
	_ = apiKeys.Revoke(ctx, res.Key.ID)

	if !hookCreateRan || !hookAuthRan || !hookRevokeRan {
		t.Fatalf("expected all hooks to execute: create=%v, auth=%v, revoke=%v",
			hookCreateRan, hookAuthRan, hookRevokeRan)
	}

	mu.Lock()
	defer mu.Unlock()
	expectedEvents := []auth.EventName{
		apikeys.EventAPIKeyCreated,
		apikeys.EventAPIKeyAuthenticated,
		apikeys.EventAPIKeyRevoked,
	}
	for _, expected := range expectedEvents {
		found := false
		for _, ev := range eventsReceived {
			if ev == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected event: %s", expected)
		}
	}
}
