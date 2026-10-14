package sqlite_test

import (
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/adapters/sqlite"
)

func TestInterfaceCompliance(t *testing.T) {
	var _ adapter.Adapter = (*sqlite.Adapter)(nil)
}

func TestAdapterInstantiation(t *testing.T) {
	ad := sqlite.New(nil)
	if ad == nil {
		t.Fatal("expected non-nil adapter")
	}
	if ad.Dialect().Name() != "sqlite" {
		t.Errorf("expected dialect sqlite, got %s", ad.Dialect().Name())
	}
}

func TestAuthEngineIntegrationWithSQLiteAdapter(t *testing.T) {
	ad := sqlite.New(nil)
	engine, err := auth.New(auth.Config{
		Adapter: ad,
	})
	if err != nil {
		t.Fatalf("auth.New with sqlite adapter failed: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}
