package sdk

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/BladiCreator/go-modular-auth/adapter"
)

var (
	// ErrAdapterNotConfigured is returned when attempting to access the database without an active adapter.
	ErrAdapterNotConfigured = errors.New("sdk db: adapter not configured")
)

// DB is the database access client exposed to plugin modules.
type DB struct {
	adapter adapter.Adapter
}

// Adapter returns the underlying generic storage adapter.
func (db *DB) Adapter() adapter.Adapter {
	if db == nil {
		return nil
	}
	return db.adapter
}

// Repository provides a strongly typed generic data access contract over a specific model.
type Repository[T any] struct {
	adapter   adapter.Adapter
	modelName string
}

// Model returns a typed Repository for the specified model using the plugin context.
//
// Usage:
//
//	repo := sdk.Model[FactorRecord](ctx, "two_factors")
//	record, err := repo.FindOne(ctx, adapter.Eq("user_id", uid))
func Model[T any](c *Context, modelName string) *Repository[T] {
	if c == nil {
		return &Repository[T]{modelName: modelName}
	}
	return &Repository[T]{
		adapter:   c.Adapter(),
		modelName: modelName,
	}
}

// For creates a typed Repository from a DB instance.
func For[T any](db *DB, modelName string) *Repository[T] {
	if db == nil {
		return &Repository[T]{modelName: modelName}
	}
	return &Repository[T]{
		adapter:   db.adapter,
		modelName: modelName,
	}
}

// FromAdapter creates a typed Repository directly from an adapter (e.g. inside a transaction).
func FromAdapter[T any](a adapter.Adapter, modelName string) *Repository[T] {
	return &Repository[T]{
		adapter:   a,
		modelName: modelName,
	}
}

// Create inserts a typed entity into the model.
func (r *Repository[T]) Create(ctx context.Context, entity *T) error {
	if r.adapter == nil {
		return ErrAdapterNotConfigured
	}
	m, err := toMap(entity)
	if err != nil {
		return err
	}
	res, err := r.adapter.Create(ctx, r.modelName, m)
	if err != nil {
		return err
	}
	return fromMap(res, entity)
}

// FindOne returns the first entity matching all given conditions.
func (r *Repository[T]) FindOne(ctx context.Context, where ...adapter.Condition) (*T, error) {
	if r.adapter == nil {
		return nil, ErrAdapterNotConfigured
	}
	row, err := r.adapter.FindOne(ctx, r.modelName, where)
	if err != nil {
		return nil, err
	}
	var entity T
	if err := fromMap(row, &entity); err != nil {
		return nil, err
	}
	return &entity, nil
}

// FindMany returns all entities matching the query.
func (r *Repository[T]) FindMany(ctx context.Context, q adapter.Query) ([]T, error) {
	if r.adapter == nil {
		return nil, ErrAdapterNotConfigured
	}
	q.Model = r.modelName
	rows, err := r.adapter.FindMany(ctx, q)
	if err != nil {
		return nil, err
	}
	results := make([]T, len(rows))
	for i, row := range rows {
		if err := fromMap(row, &results[i]); err != nil {
			return nil, err
		}
	}
	return results, nil
}

// Update modifies matching records in the model.
func (r *Repository[T]) Update(ctx context.Context, where []adapter.Condition, update map[string]any) (int64, error) {
	if r.adapter == nil {
		return 0, ErrAdapterNotConfigured
	}
	return r.adapter.Update(ctx, r.modelName, where, update)
}

// Delete removes matching records from the model.
func (r *Repository[T]) Delete(ctx context.Context, where ...adapter.Condition) (int64, error) {
	if r.adapter == nil {
		return 0, ErrAdapterNotConfigured
	}
	return r.adapter.Delete(ctx, r.modelName, where)
}

// Count returns the count of matching records.
func (r *Repository[T]) Count(ctx context.Context, where ...adapter.Condition) (int64, error) {
	if r.adapter == nil {
		return 0, ErrAdapterNotConfigured
	}
	return r.adapter.Count(ctx, r.modelName, where)
}

func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func fromMap(m map[string]any, v any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
