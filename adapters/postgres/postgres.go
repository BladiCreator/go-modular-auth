// Package postgres provides a production-grade PostgreSQL implementation of adapter.Adapter.
//
// It operates dynamically over the compiled schema (Core + Plugins), handling DDL generation,
// query building, transactional isolation via sqltx, and SQLSTATE error mapping.
package postgres

import (
	"database/sql"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sqladapter "github.com/BladiCreator/go-modular-auth/adapter/sql"
)

// Adapter is the PostgreSQL implementation of adapter.Adapter.
type Adapter struct {
	*sqladapter.BaseAdapter
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.SchemaExporter = (*Adapter)(nil)

// New creates a PostgreSQL storage adapter satisfying adapter.Adapter.
func New(db *sql.DB) *Adapter {
	return &Adapter{
		BaseAdapter: sqladapter.New(db, sqladapter.Postgres),
	}
}
