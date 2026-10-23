// Package mysql provides a MySQL 8.0+ implementation of adapter.Adapter.
//
// It operates dynamically over the compiled schema (Core + Plugins), handling DDL generation,
// query building, transactional isolation via sqltx, and MySQL 1062 error mapping.
package mysql

import (
	"database/sql"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sqladapter "github.com/BladiCreator/go-modular-auth/adapter/sql"
)

// Adapter is the MySQL implementation of adapter.Adapter.
type Adapter struct {
	*sqladapter.BaseAdapter
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.SchemaExporter = (*Adapter)(nil)

// New creates a MySQL storage adapter satisfying adapter.Adapter.
func New(db *sql.DB) *Adapter {
	return &Adapter{
		BaseAdapter: sqladapter.New(db, sqladapter.MySQL),
	}
}
