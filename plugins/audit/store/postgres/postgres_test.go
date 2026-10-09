package postgres_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/BladiCreator/go-modular-auth-audit/store"
	"github.com/BladiCreator/go-modular-auth-audit/store/postgres"
)

func TestPostgresStoreInterface(t *testing.T) {
	// Verify postgres.Store satisfies store.Store contract
	var _ store.Store = (*postgres.Store)(nil)

	pStore := postgres.New(&sql.DB{})
	if pStore == nil {
		t.Fatal("expected non-nil postgres store")
	}

	// Verify cancelled context returns context error
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := pStore.Record(ctx, &store.AuditRecord{
		ID:    "aud_pg_test",
		Event: "test.event",
	})
	if err == nil {
		t.Fatal("expected error on cancelled context with closed db")
	}
}
