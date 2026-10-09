package postgres_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/BladiCreator/go-modular-auth-device-authorization/store"
	"github.com/BladiCreator/go-modular-auth-device-authorization/store/postgres"
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

	err := pStore.Create(ctx, &store.DeviceGrant{
		ID:             "grant_pg_test",
		ClientID:       "client_test",
		DeviceCodeHash: "hash_test",
		UserCode:       "TEST-1234",
	})
	if err == nil {
		t.Fatal("expected error on cancelled context with closed db")
	}
}
