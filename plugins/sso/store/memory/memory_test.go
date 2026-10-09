package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-sso/store"
	"github.com/BladiCreator/go-modular-auth-sso/store/memory"
)

func TestMemoryStore_ConfigLifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	cfg := &store.SSOConfig{
		ID:             "cfg-1",
		OrganizationID: "org-acme",
		Name:           "Acme Okta",
		Protocol:       store.ProtocolOIDC,
		Enabled:        true,
		Domains:        []string{"acme.com", "acmecorp.com"},
		JITEnabled:     true,
		DefaultRole:    "member",
		OIDC: &store.OIDCConfig{
			Issuer:   "https://okta.acme.com",
			ClientID: "client-id-xyz",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 1. SaveConfig
	if err := s.SaveConfig(ctx, cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// 2. Conflict on duplicate config
	if err := s.SaveConfig(ctx, cfg); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	// 3. Domain conflict with another organization
	cfgOther := &store.SSOConfig{
		ID:             "cfg-2",
		OrganizationID: "org-other",
		Name:           "Other Okta",
		Protocol:       store.ProtocolOIDC,
		Enabled:        true,
		Domains:        []string{"acme.com"},
	}
	if err := s.SaveConfig(ctx, cfgOther); !errors.Is(err, store.ErrDomainClaimed) {
		t.Fatalf("expected ErrDomainClaimed, got %v", err)
	}

	// 4. GetConfig
	got, err := s.GetConfig(ctx, "org-acme", "cfg-1")
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if got.Name != "Acme Okta" || len(got.Domains) != 2 {
		t.Errorf("unexpected retrieved config: %+v", got)
	}

	// 5. GetConfigByDomain
	byDomain, err := s.GetConfigByDomain(ctx, "acme.com")
	if err != nil {
		t.Fatalf("GetConfigByDomain failed: %v", err)
	}
	if byDomain.ID != "cfg-1" {
		t.Errorf("expected cfg-1, got %s", byDomain.ID)
	}

	// 6. UpdateConfig
	got.Name = "Acme Okta Updated"
	got.Domains = []string{"acme.com", "newacme.com"}
	if err := s.UpdateConfig(ctx, got); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	// Verify old domain deleted and new domain queryable
	if _, err := s.GetConfigByDomain(ctx, "acmecorp.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for removed domain, got %v", err)
	}
	if _, err := s.GetConfigByDomain(ctx, "newacme.com"); err != nil {
		t.Errorf("expected to find newacme.com, got %v", err)
	}

	// 7. DeleteConfig
	if err := s.DeleteConfig(ctx, "org-acme", "cfg-1"); err != nil {
		t.Fatalf("DeleteConfig failed: %v", err)
	}
	if _, err := s.GetConfig(ctx, "org-acme", "cfg-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound after deletion, got %v", err)
	}
	if _, err := s.GetConfigByDomain(ctx, "acme.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected domain unmapped after deletion, got %v", err)
	}
}

func TestMemoryStore_StateLifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	state := &store.SSOStateSession{
		State:          "state-token-123",
		OrganizationID: "org-acme",
		ConfigID:       "cfg-1",
		Protocol:       store.ProtocolOIDC,
		RedirectURI:    "https://app.com/cb",
		Nonce:          "nonce-123",
		ExpiresAt:      now.Add(10 * time.Minute),
		CreatedAt:      now,
	}

	if err := s.SaveState(ctx, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Duplicate state
	if err := s.SaveState(ctx, state); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	// ConsumeState
	consumed, err := s.ConsumeState(ctx, "state-token-123", now)
	if err != nil {
		t.Fatalf("ConsumeState failed: %v", err)
	}
	if !consumed.IsConsumed() {
		t.Fatalf("expected consumed state")
	}

	// Replay attempt
	if _, err := s.ConsumeState(ctx, "state-token-123", now); !errors.Is(err, store.ErrStateConsumed) {
		t.Fatalf("expected ErrStateConsumed on replay, got %v", err)
	}

	// PurgeExpired
	expiredState := &store.SSOStateSession{
		State:     "expired-state",
		ExpiresAt: now.Add(-5 * time.Minute),
	}
	_ = s.SaveState(ctx, expiredState)

	purged, err := s.PurgeExpiredStates(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpiredStates failed: %v", err)
	}
	if purged != 1 {
		t.Errorf("expected 1 purged state, got %d", purged)
	}
}
