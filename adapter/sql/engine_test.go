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
