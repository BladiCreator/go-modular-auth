package postgres_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/BladiCreator/go-modular-auth-admin/store"
	"github.com/BladiCreator/go-modular-auth-admin/store/postgres"
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

	err := pStore.UpsertUser(ctx, &store.UserRecord{
		UserID: "usr_test",
		Email:  "test@example.com",
	})
	if err == nil {
		t.Fatal("expected error on cancelled context with closed db")
	}
}
