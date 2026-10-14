package mysql_test

import (
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/adapters/mysql"
)

func TestInterfaceCompliance(t *testing.T) {
	var _ adapter.Adapter = (*mysql.Adapter)(nil)
}

func TestAdapterInstantiation(t *testing.T) {
	ad := mysql.New(nil)
	if ad == nil {
		t.Fatal("expected non-nil adapter")
	}
	if ad.Dialect().Name() != "mysql" {
		t.Errorf("expected dialect mysql, got %s", ad.Dialect().Name())
	}
}

func TestAuthEngineIntegrationWithMySQLAdapter(t *testing.T) {
	ad := mysql.New(nil)
	engine, err := auth.New(auth.Config{
		Adapter: ad,
	})
	if err != nil {
		t.Fatalf("auth.New with mysql adapter failed: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}
