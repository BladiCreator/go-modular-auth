package surrealdb

import (
	"strings"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/surrealdb/surrealdb.go/pkg/connection"
)

// MapError translates SurrealDB driver and server errors into canonical adapter errors.
func MapError(err error) error {
	if err == nil {
		return nil
	}

	// Canonical sentinel errors
	if err == adapter.ErrNotFound || err == adapter.ErrConflict {
		return err
	}

	// Structured ServerError checks
	if se, ok := err.(*connection.ServerError); ok && se != nil {
		switch se.Kind {
		case connection.KindAlreadyExists:
			return adapter.ErrConflict
		case connection.KindNotFound:
			return adapter.ErrNotFound
		}
	}
	if se, ok := err.(connection.ServerError); ok {
		switch se.Kind {
		case connection.KindAlreadyExists:
			return adapter.ErrConflict
		case connection.KindNotFound:
			return adapter.ErrNotFound
		}
	}

	// SurrealDB connection predicate helpers
	if connection.IsNotFound(err) {
		return adapter.ErrNotFound
	}
	if connection.IsTransactionConflict(err) {
		return adapter.ErrConflict
	}

	// Fallback textual inspections
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "record conflict") ||
		strings.Contains(msg, "unique index") ||
		strings.Contains(msg, "duplicate") {
		return adapter.ErrConflict
	}
	if strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist") {
		return adapter.ErrNotFound
	}

	return err
}
