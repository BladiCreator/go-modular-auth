package sqlite_test

import (
	"strings"
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapters/sqlite"
	"github.com/BladiCreator/go-modular-auth/store"
)

func TestInterfaceCompliance(t *testing.T) {
	var _ store.Store = (*sqlite.Store)(nil)
}

func TestSchemaDDL(t *testing.T) {
	ddl := sqlite.SchemaDDL

	requiredTables := []string{
		"auth_users",
		"auth_accounts",
		"auth_credentials",
		"auth_sessions",
		"auth_verification_tokens",
	}

	for _, table := range requiredTables {
		if !strings.Contains(ddl, table) {
			t.Errorf("SchemaDDL missing required table %s", table)
		}
	}
}

func TestStoreInstantiation(t *testing.T) {
	s := sqlite.New(nil)
	if s.Users() == nil {
		t.Error("expected non-nil Users store")
	}
	if s.Accounts() == nil {
		t.Error("expected non-nil Accounts store")
	}
	if s.Credentials() == nil {
		t.Error("expected non-nil Credentials store")
	}
	if s.Sessions() == nil {
		t.Error("expected non-nil Sessions store")
	}
	if s.Tokens() == nil {
		t.Error("expected non-nil Tokens store")
	}
}
