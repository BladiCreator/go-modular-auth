package postgres_test

import (
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/adapters/postgres"
)

func TestInterfaceCompliance(t *testing.T) {
	var _ adapter.Adapter = (*postgres.Adapter)(nil)
}

func TestAdapterInstantiation(t *testing.T) {
	ad := postgres.New(nil)
	if ad == nil {
		t.Fatal("expected non-nil adapter")
	}
	if ad.Dialect().Name() != "postgres" {
		t.Errorf("expected dialect postgres, got %s", ad.Dialect().Name())
	}
}

func TestAuthEngineIntegrationWithPostgresAdapter(t *testing.T) {
	ad := postgres.New(nil)
	engine, err := auth.New(auth.Config{
		Adapter: ad,
	})
	if err != nil {
		t.Fatalf("auth.New with postgres adapter failed: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}
