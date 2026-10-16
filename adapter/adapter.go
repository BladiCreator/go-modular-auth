// Package adapter defines the generic, schema-driven persistence contracts for GoModularAuth.
//
// Unlike static domain repository interfaces, an Adapter executes generic CRUD operations
// parameterized by model name and declarative query conditions. This decouples storage
// drivers (PostgreSQL, SQLite, MySQL, Memory) from individual plugin domain types.
package adapter

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/schema"
)

var (
	// ErrNotFound is returned when a record matching the query criteria does not exist.
	ErrNotFound = errors.New("adapter: record not found")
	// ErrConflict is returned when an insert or update violates a unique constraint or primary key.
	ErrConflict = errors.New("adapter: record conflict")
)

// Operator represents a logical comparison operator for query conditions.
type Operator string

const (
	OpEq        Operator = "="
	OpNe        Operator = "!="
	OpGt        Operator = ">"
	OpGte       Operator = ">="
	OpLt        Operator = "<"
	OpLte       Operator = "<="
	OpIn        Operator = "IN"
	OpLike      Operator = "LIKE"
	OpIsNull    Operator = "IS NULL"
	OpIsNotNull Operator = "IS NOT NULL"
)

// Condition represents a single predicate applied to a model field.
type Condition struct {
	Field    string
	Operator Operator
	Value    any
}

// Eq creates an equality condition (field = val).
func Eq(field string, val any) Condition {
	return Condition{Field: field, Operator: OpEq, Value: val}
}

// Ne creates an inequality condition (field != val).
func Ne(field string, val any) Condition {
	return Condition{Field: field, Operator: OpNe, Value: val}
}

// Gt creates a greater-than condition (field > val).
func Gt(field string, val any) Condition {
	return Condition{Field: field, Operator: OpGt, Value: val}
}

// Gte creates a greater-than-or-equal condition (field >= val).
func Gte(field string, val any) Condition {
	return Condition{Field: field, Operator: OpGte, Value: val}
}

// Lt creates a less-than condition (field < val).
func Lt(field string, val any) Condition {
	return Condition{Field: field, Operator: OpLt, Value: val}
}

// Lte creates a less-than-or-equal condition (field <= val).
func Lte(field string, val any) Condition {
	return Condition{Field: field, Operator: OpLte, Value: val}
}

// In creates an IN condition (field IN (vals...)).
func In(field string, vals ...any) Condition {
	return Condition{Field: field, Operator: OpIn, Value: vals}
}

// IsNull creates an IS NULL condition.
func IsNull(field string) Condition {
	return Condition{Field: field, Operator: OpIsNull}
}

// IsNotNull creates an IS NOT NULL condition.
func IsNotNull(field string) Condition {
	return Condition{Field: field, Operator: OpIsNotNull}
}

// Query defines search, sorting, and pagination parameters for finding multiple records.
type Query struct {
	Model  string
	Where  []Condition
	Limit  int
	Offset int
	SortBy string
	Desc   bool
}

// Adapter is the polymorphic storage engine interface implemented by databases.
//
// All database adapters (Postgres, SQLite, MySQL, Memory) implement this single
// interface, allowing plugins to declare new models and fields without needing
// engine-specific repository implementations.
type Adapter interface {
	// RegisterSchema provides the compiled schema to the adapter, allowing
	// it to map fields, understand constraints, and prepare statements or tables.
	RegisterSchema(ctx context.Context, s *schema.Schema) error

	// Create inserts a single record into the given model. It returns the persisted
	// data (including database defaults or auto-generated IDs).
	// Returns ErrConflict on unique constraint violations.
	Create(ctx context.Context, model string, data map[string]any) (map[string]any, error)

	// FindOne retrieves the first record matching all conditions, or ErrNotFound if none match.
	FindOne(ctx context.Context, model string, where []Condition) (map[string]any, error)

	// FindMany retrieves all records matching the query criteria.
	FindMany(ctx context.Context, q Query) ([]map[string]any, error)

	// Update modifies records matching the conditions and returns the number of rows affected.
	Update(ctx context.Context, model string, where []Condition, update map[string]any) (int64, error)

	// Delete removes records matching the conditions and returns the number of rows affected.
	Delete(ctx context.Context, model string, where []Condition) (int64, error)

	// Count returns the number of records matching the given conditions.
	Count(ctx context.Context, model string, where []Condition) (int64, error)

	// Transaction executes fn atomically within a database transaction.
	// Nested transactions join the parent transaction.
	Transaction(ctx context.Context, fn func(ctx context.Context, tx Adapter) error) error
}
