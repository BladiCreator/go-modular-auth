package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-saml/store"
	"github.com/BladiCreator/go-modular-auth-saml/store/memory"
)

func TestMemoryStore_IdPAndRequestLifecycle(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	now := time.Now().UTC()

	cfg := &store.IdPConfig{
		ID:             "idp-1",
		OrganizationID: "org-1",
		EntityID:       "https://idp.example.com",
		SSOURL:         "https://idp.example.com/sso",
		Enabled:        true,
	}

	if err := s.SaveIdP(ctx, cfg); err != nil {
		t.Fatalf("SaveIdP failed: %v", err)
	}

	// Conflict
	if err := s.SaveIdP(ctx, cfg); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate, got %v", err)
	}

	// Lookup by entity ID
	byEntity, err := s.GetIdPByEntityID(ctx, "https://idp.example.com")
	if err != nil || byEntity.ID != "idp-1" {
		t.Fatalf("GetIdPByEntityID failed: %v", err)
	}

	// Request Session
	req := &store.RequestSession{
		ID:         "_req_123",
		ProviderID: "idp-1",
		ExpiresAt:  now.Add(5 * time.Minute),
		CreatedAt:  now,
	}
	if err := s.SaveRequest(ctx, req); err != nil {
		t.Fatalf("SaveRequest failed: %v", err)
	}

	consumed, err := s.ConsumeRequest(ctx, "_req_123", now)
	if err != nil || !consumed.IsConsumed() {
		t.Fatalf("ConsumeRequest failed: %v", err)
	}

	// Replay request
	if _, err := s.ConsumeRequest(ctx, "_req_123", now); !errors.Is(err, store.ErrRequestConsumed) {
		t.Fatalf("expected ErrRequestConsumed, got %v", err)
	}

	// Assertion Replay tracking
	assertID := "_assert_999"
	exp := now.Add(10 * time.Minute)
	if err := s.RecordAssertion(ctx, assertID, "idp-1", exp, now); err != nil {
		t.Fatalf("RecordAssertion failed: %v", err)
	}

	// Second attempt within validity window
	if err := s.RecordAssertion(ctx, assertID, "idp-1", exp, now); !errors.Is(err, store.ErrAssertionReplayed) {
		t.Fatalf("expected ErrAssertionReplayed, got %v", err)
	}
}
