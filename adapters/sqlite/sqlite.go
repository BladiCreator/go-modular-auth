// Package sqlite provides an SQLite implementation of adapter.Adapter.
//
// It operates dynamically over the compiled schema (Core + Plugins), handling DDL generation,
// query building, transactional isolation via sqltx, and SQLite constraint error mapping.
package sqlite

import (
	"database/sql"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sqladapter "github.com/BladiCreator/go-modular-auth/adapter/sql"
)

// Adapter is the SQLite implementation of adapter.Adapter.
type Adapter struct {
	*sqladapter.BaseAdapter
}

var _ adapter.Adapter = (*Adapter)(nil)

// New creates an SQLite storage adapter satisfying adapter.Adapter.
func New(db *sql.DB) *Adapter {
	return &Adapter{
		BaseAdapter: sqladapter.New(db, sqladapter.SQLite),
	}
}
