// Package sqladapter provides generic SQL dialect handling and a base relational adapter.
package sqladapter

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// Dialect abstracts SQL syntax differences across database engines.
type Dialect interface {
	Name() string
	Placeholder(index int) string
	Quote(name string) string
	DataType(dt schema.DataType) string
	MapError(err error) error
}

// --- PostgreSQL Dialect ---

type postgresDialect struct{}

// Postgres returns the PostgreSQL dialect implementation.
var Postgres Dialect = &postgresDialect{}

func (d *postgresDialect) Name() string { return "postgres" }

func (d *postgresDialect) Placeholder(index int) string {
	return fmt.Sprintf("$%d", index)
}

func (d *postgresDialect) Quote(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func (d *postgresDialect) DataType(dt schema.DataType) string {
	switch dt {
	case schema.TypeString:
		return "VARCHAR(255)"
	case schema.TypeInt64:
		return "BIGINT"
	case schema.TypeFloat64:
		return "DOUBLE PRECISION"
	case schema.TypeBool:
		return "BOOLEAN"
	case schema.TypeTime:
		return "TIMESTAMPTZ"
	case schema.TypeBytes:
		return "BYTEA"
	case schema.TypeJSON:
		return "JSONB"
	default:
		return "TEXT"
	}
}

func (d *postgresDialect) MapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return adapter.ErrNotFound
	}
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "unique constraint") ||
		strings.Contains(errMsg, "duplicate key") ||
		strings.Contains(errMsg, "23505") {
		return fmt.Errorf("%w: %v", adapter.ErrConflict, err)
	}
	return err
}

// --- SQLite Dialect ---

type sqliteDialect struct{}

// SQLite returns the SQLite dialect implementation.
var SQLite Dialect = &sqliteDialect{}

func (d *sqliteDialect) Name() string { return "sqlite" }

func (d *sqliteDialect) Placeholder(_ int) string {
	return "?"
}

func (d *sqliteDialect) Quote(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func (d *sqliteDialect) DataType(dt schema.DataType) string {
	switch dt {
	case schema.TypeString:
		return "TEXT"
	case schema.TypeInt64:
		return "INTEGER"
	case schema.TypeFloat64:
		return "REAL"
	case schema.TypeBool:
		return "INTEGER"
	case schema.TypeTime:
		return "DATETIME"
	case schema.TypeBytes:
		return "BLOB"
	case schema.TypeJSON:
		return "TEXT"
	default:
		return "TEXT"
	}
}

func (d *sqliteDialect) MapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return adapter.ErrNotFound
	}
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "unique constraint failed") ||
		strings.Contains(errMsg, "constraint failed") {
		return fmt.Errorf("%w: %v", adapter.ErrConflict, err)
	}
	return err
}

// --- MySQL Dialect ---

type mysqlDialect struct{}

// MySQL returns the MySQL dialect implementation.
var MySQL Dialect = &mysqlDialect{}

func (d *mysqlDialect) Name() string { return "mysql" }

func (d *mysqlDialect) Placeholder(_ int) string {
	return "?"
}

func (d *mysqlDialect) Quote(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

func (d *mysqlDialect) DataType(dt schema.DataType) string {
	switch dt {
	case schema.TypeString:
		return "VARCHAR(255)"
	case schema.TypeInt64:
		return "BIGINT"
	case schema.TypeFloat64:
		return "DOUBLE"
	case schema.TypeBool:
		return "BOOLEAN"
	case schema.TypeTime:
		return "DATETIME(6)"
	case schema.TypeBytes:
		return "BLOB"
	case schema.TypeJSON:
		return "JSON"
	default:
		return "TEXT"
	}
}

func (d *mysqlDialect) MapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return adapter.ErrNotFound
	}
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "1062") ||
		strings.Contains(errMsg, "duplicate entry") {
		return fmt.Errorf("%w: %v", adapter.ErrConflict, err)
	}
	return err
}
