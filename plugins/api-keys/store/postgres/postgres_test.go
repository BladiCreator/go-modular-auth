package postgres_test

import (
	"testing"

	"github.com/BladiCreator/go-modular-auth-apikeys/store"
	"github.com/BladiCreator/go-modular-auth-apikeys/store/postgres"
)

func TestPostgresStore_ImplementsStore(t *testing.T) {
	var _ store.Store = (*postgres.Store)(nil)

	s := postgres.New(nil)
	if s == nil {
		t.Fatal("expected non-nil Postgres store")
	}
}
