// Package sqltx provides the shared database/sql transaction context used by
// every SQL store adapter of GoModularAuth (core and plugins).
//
// Each store used to carry its own private context key, so a transaction
// opened by the core Store was invisible to plugin stores and vice versa.
// Routing every SQL adapter through this package gives a single transaction
// boundary: any store whose *sql.DB points at the same database joins the
// transaction found in ctx.
//
// Joining is only meaningful when the stores share the same database. Stores
// configured against a different database must not be called with a
// transactional ctx coming from another database.
package sqltx

import (
	"context"
	"database/sql"
	"errors"
)

// DBTX is the subset of *sql.DB and *sql.Tx used by store adapters.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

var (
	_ DBTX = (*sql.DB)(nil)
	_ DBTX = (*sql.Tx)(nil)
)

type txKey struct{}

// WithTx returns a context carrying tx.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// TxFrom returns the transaction carried by ctx, if any.
func TxFrom(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(*sql.Tx)
	return tx, ok && tx != nil
}

// Executor returns the transaction in ctx, or db when ctx carries none.
func Executor(ctx context.Context, db *sql.DB) DBTX {
	if tx, ok := TxFrom(ctx); ok {
		return tx
	}
	return db
}

// Run executes fn atomically. When ctx already carries a transaction, fn
// joins it (nested calls never open a second transaction). Otherwise a new
// transaction is started, committed when fn returns nil and rolled back on
// error or panic.
func Run(ctx context.Context, db *sql.DB, opts *sql.TxOptions, fn func(ctx context.Context) error) (err error) {
	if _, ok := TxFrom(ctx); ok {
		return fn(ctx)
	}
	if db == nil {
		return errors.New("sqltx: nil *sql.DB")
	}
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(WithTx(ctx, tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}
