package sqladapter_test

import (
	"testing"

	sqladapter "github.com/BladiCreator/go-modular-auth/adapter/sql"
	"github.com/BladiCreator/go-modular-auth/schema"
)

func TestDialects_PlaceholdersAndQuotes(t *testing.T) {
	pg := sqladapter.Postgres
	if pg.Placeholder(1) != "$1" || pg.Placeholder(2) != "$2" {
		t.Errorf("postgres placeholder mismatch: %v", pg.Placeholder(1))
	}
	if pg.Quote("users") != `"users"` {
		t.Errorf("postgres quote mismatch: %v", pg.Quote("users"))
	}

	sqlite := sqladapter.SQLite
	if sqlite.Placeholder(1) != "?" {
		t.Errorf("sqlite placeholder mismatch: %v", sqlite.Placeholder(1))
	}
	if sqlite.Quote("users") != `"users"` {
		t.Errorf("sqlite quote mismatch: %v", sqlite.Quote("users"))
	}

	mysql := sqladapter.MySQL
	if mysql.Placeholder(1) != "?" {
		t.Errorf("mysql placeholder mismatch: %v", mysql.Placeholder(1))
	}
	if mysql.Quote("users") != "`users`" {
		t.Errorf("mysql quote mismatch: %v", mysql.Quote("users"))
	}
}

func TestDialects_DataTypes(t *testing.T) {
	if sqladapter.Postgres.DataType(schema.TypeTime) != "TIMESTAMPTZ" {
		t.Errorf("expected TIMESTAMPTZ for Postgres time")
	}
	if sqladapter.SQLite.DataType(schema.TypeTime) != "DATETIME" {
		t.Errorf("expected DATETIME for SQLite time")
	}
	if sqladapter.MySQL.DataType(schema.TypeTime) != "DATETIME(6)" {
		t.Errorf("expected DATETIME(6) for MySQL time")
	}
}

func TestBaseAdapter_ExportSchema(t *testing.T) {
	s := schema.New()
	mUsers := schema.NewModel("users", "users", "id")
	_ = mUsers.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = mUsers.AddField(schema.Field{Name: "email", Type: schema.TypeString, Required: true, Unique: true})
	_ = mUsers.AddField(schema.Field{Name: "age", Type: schema.TypeInt64})
	mUsers.Indexes = append(mUsers.Indexes, schema.Index{Name: "idx_users_age", Fields: []string{"age"}})
	_ = s.AddModel(mUsers)

	tests := []struct {
		name        string
		dialect     sqladapter.Dialect
		expectedSub string
		expectedIdx string
	}{
		{
			name:        "PostgreSQL",
			dialect:     sqladapter.Postgres,
			expectedSub: `CREATE TABLE IF NOT EXISTS "users" ("id" VARCHAR(255) PRIMARY KEY, "age" BIGINT, "email" VARCHAR(255) NOT NULL UNIQUE)`,
			expectedIdx: `CREATE INDEX IF NOT EXISTS "idx_users_age" ON "users" ("age")`,
		},
		{
			name:        "SQLite",
			dialect:     sqladapter.SQLite,
			expectedSub: `CREATE TABLE IF NOT EXISTS "users" ("id" TEXT PRIMARY KEY, "age" INTEGER, "email" TEXT NOT NULL UNIQUE)`,
			expectedIdx: `CREATE INDEX IF NOT EXISTS "idx_users_age" ON "users" ("age")`,
		},
		{
			name:        "MySQL",
			dialect:     sqladapter.MySQL,
			expectedSub: "CREATE TABLE IF NOT EXISTS `users` (`id` VARCHAR(255) PRIMARY KEY, `age` BIGINT, `email` VARCHAR(255) NOT NULL UNIQUE)",
			expectedIdx: "CREATE INDEX IF NOT EXISTS `idx_users_age` ON `users` (`age`)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ba := sqladapter.New(nil, tt.dialect)

			// 1. Should error when no schema registered
			if _, err := ba.ExportSchema(t.Context()); err == nil {
				t.Fatal("expected error when exporting without schema")
			}

			if err := ba.RegisterSchema(t.Context(), s); err != nil {
				t.Fatalf("RegisterSchema failed: %v", err)
			}

			stmts1, err := ba.ExportSchema(t.Context())
			if err != nil {
				t.Fatalf("ExportSchema failed: %v", err)
			}

			// Determinism check
			stmts2, err := ba.ExportSchema(t.Context())
			if err != nil {
				t.Fatalf("second ExportSchema failed: %v", err)
			}
			if len(stmts1) != len(stmts2) {
				t.Fatalf("length mismatch: %d vs %d", len(stmts1), len(stmts2))
			}
			for i := range stmts1 {
				if stmts1[i] != stmts2[i] {
					t.Fatalf("non-deterministic output at %d: %q vs %q", i, stmts1[i], stmts2[i])
				}
			}

			if len(stmts1) != 2 {
				t.Fatalf("expected 2 statements (CREATE TABLE + CREATE INDEX), got %d: %v", len(stmts1), stmts1)
			}
			if stmts1[0] != tt.expectedSub {
				t.Errorf("expected table DDL:\n%s\ngot:\n%s", tt.expectedSub, stmts1[0])
			}
			if stmts1[1] != tt.expectedIdx {
				t.Errorf("expected index DDL:\n%s\ngot:\n%s", tt.expectedIdx, stmts1[1])
			}
		})
	}
}
