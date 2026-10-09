package postgres_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth-oauth/store"
	"github.com/BladiCreator/go-modular-auth-oauth/store/postgres"
)

func TestPostgresStoreInterface(t *testing.T) {
	// Verify postgres.Store satisfies store.Store contract
	var _ store.Store = (*postgres.Store)(nil)

	// Passing nil sql.DB should initialize struct cleanly
	pStore := postgres.New(&sql.DB{})
	if pStore == nil {
		t.Fatal("expected non-nil postgres store")
	}

	// StateSession model validation
	now := time.Now()
	s := &store.StateSession{
		State:       "pg_state",
		Provider:    "google",
		RedirectURI: "https://example.com/callback",
		Action:      store.ActionSignIn,
		ExpiresAt:   now.Add(5 * time.Minute),
		CreatedAt:   now,
	}

	if s.Expired(now) {
		t.Fatal("session should not be expired")
	}
	if s.Consumed() {
		t.Fatal("session should not be consumed")
	}
	if !s.Valid(now) {
		t.Fatal("session should be valid")
	}

	// Mark consumed
	s.ConsumedAt = &now
	if !s.Consumed() {
		t.Fatal("session should be consumed")
	}
	if s.Valid(now) {
		t.Fatal("consumed session should not be valid")
	}

	// Cancel context error check
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := pStore.SaveState(ctx, s)
	if err == nil {
		t.Fatal("expected error on cancelled context with closed db")
	}
}
