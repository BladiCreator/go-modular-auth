// Package surrealdb provides a SurrealDB implementation of adapter.Adapter.
//
// It operates over the compiled schema (Core + Plugins), handling SurrealQL DDL generation,
// parameterized query building, and SurrealDB error mapping.
package surrealdb

import (
	"context"
	"time"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/schema"
	surreal "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Adapter is the SurrealDB implementation of adapter.Adapter.
type Adapter struct {
	db     *surreal.DB
	tx     *surreal.Transaction
	schema *schema.Schema
	mu     sync.RWMutex
}

var _ adapter.Adapter = (*Adapter)(nil)

// New creates a SurrealDB adapter wrapping an established *surreal.DB client.
func New(db *surreal.DB) *Adapter {
	return &Adapter{
		db: db,
	}
}

// NewFromConfig connects to SurrealDB using the given Config and returns an initialized Adapter.
func NewFromConfig(ctx context.Context, cfg Config) (*Adapter, error) {
	db, err := cfg.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return New(db), nil
}

// DB returns the underlying SurrealDB client.
func (a *Adapter) DB() *surreal.DB {
	return a.db
}

// Close closes the underlying SurrealDB connection.
func (a *Adapter) Close(ctx context.Context) error {
	if a.db != nil {
		return a.db.Close(ctx)
	}
	return nil
}

// Create inserts a single record into the given model collection.
func (a *Adapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	if data == nil {
		data = make(map[string]any)
	}

	pkField := "id"
	a.mu.RLock()
	if a.schema != nil {
		if m, ok := a.schema.GetModel(model); ok && m.PrimaryKey != "" {
			pkField = m.PrimaryKey
		}
	}
	a.mu.RUnlock()

	pkVal, hasPK := data[pkField]
	payload := make(map[string]any, len(data))
	for k, v := range data {
		if k == pkField && hasPK {
			continue
		}
		payload[k] = a.preparePayloadValue(model, k, v)
	}

	var res *map[string]any
	var err error
	if hasPK && pkVal != nil && fmt.Sprintf("%v", pkVal) != "" {
		res, err = createRecord[map[string]any](ctx, a, models.NewRecordID(model, pkVal), payload)
	} else {
		res, err = createRecord[map[string]any](ctx, a, models.Table(model), payload)
	}

	if err != nil {
		return nil, a.mapError(err)
	}
	if res == nil {
		return nil, fmt.Errorf("surrealdb: create returned empty result")
	}

	return normalizeRow(model, *res), nil
}

// FindOne retrieves the first record matching all conditions, or ErrNotFound if none match.
func (a *Adapter) FindOne(ctx context.Context, model string, where []adapter.Condition) (map[string]any, error) {
	q := adapter.Query{
		Model: model,
		Where: where,
		Limit: 1,
	}
	results, err := a.FindMany(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, adapter.ErrNotFound
	}
	return results[0], nil
}

// FindMany retrieves all records matching query conditions, supporting sorting and pagination.
func (a *Adapter) FindMany(ctx context.Context, q adapter.Query) ([]map[string]any, error) {
	sb := strings.Builder{}
	sb.WriteString("SELECT * FROM ")
	sb.WriteString(q.Model)

	vars := make(map[string]any)
	if len(q.Where) > 0 {
		whereClause, whereVars := buildWhere(q.Model, q.Where)
		sb.WriteString(" WHERE ")
		sb.WriteString(whereClause)
		for k, v := range whereVars {
			vars[k] = v
		}
	}

	if q.SortBy != "" {
		sb.WriteString(" ORDER BY ")
		sb.WriteString(quoteField(q.SortBy))
		if q.Desc {
			sb.WriteString(" DESC")
		} else {
			sb.WriteString(" ASC")
		}
	}

	if q.Limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", q.Limit))
	}
	if q.Offset > 0 {
		sb.WriteString(fmt.Sprintf(" START %d", q.Offset))
	}

	res, err := query[[]map[string]any](ctx, a, sb.String(), vars)
	if err != nil {
		return nil, a.mapError(err)
	}
	if res == nil || len(*res) == 0 {
		return []map[string]any{}, nil
	}

	first := (*res)[0]
	if first.Error != nil {
		return nil, a.mapError(first.Error)
	}

	rows := first.Result
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		out[i] = normalizeRow(q.Model, r)
	}
	return out, nil
}

// Update modifies records matching the conditions and returns the number of rows affected.
func (a *Adapter) Update(ctx context.Context, model string, where []adapter.Condition, update map[string]any) (int64, error) {
	if len(update) == 0 {
		return 0, nil
	}

	sb := strings.Builder{}
	sb.WriteString("UPDATE ")
	sb.WriteString(model)
	sb.WriteString(" MERGE $update_content")

	vars := make(map[string]any)
	updatePayload := make(map[string]any, len(update))
	for k, v := range update {
		if k != "id" {
			updatePayload[k] = a.preparePayloadValue(model, k, v)
		}
	}
	vars["update_content"] = updatePayload

	if len(where) > 0 {
		whereClause, whereVars := buildWhere(model, where)
		sb.WriteString(" WHERE ")
		sb.WriteString(whereClause)
		for k, v := range whereVars {
			vars[k] = v
		}
	}
	sb.WriteString(" RETURN BEFORE;")

	res, err := query[[]map[string]any](ctx, a, sb.String(), vars)
	if err != nil {
		return 0, a.mapError(err)
	}
	if res == nil || len(*res) == 0 {
		return 0, nil
	}

	first := (*res)[0]
	if first.Error != nil {
		mapped := a.mapError(first.Error)
		if errors.Is(mapped, adapter.ErrNotFound) {
			return 0, nil
		}
		return 0, mapped
	}

	return int64(len(first.Result)), nil
}

// Delete removes records matching the conditions and returns the number of rows affected.
func (a *Adapter) Delete(ctx context.Context, model string, where []adapter.Condition) (int64, error) {
	sb := strings.Builder{}
	sb.WriteString("DELETE FROM ")
	sb.WriteString(model)

	vars := make(map[string]any)
	if len(where) > 0 {
		whereClause, whereVars := buildWhere(model, where)
		sb.WriteString(" WHERE ")
		sb.WriteString(whereClause)
		for k, v := range whereVars {
			vars[k] = v
		}
	}
	sb.WriteString(" RETURN BEFORE;")

	res, err := query[[]map[string]any](ctx, a, sb.String(), vars)
	if err != nil {
		return 0, a.mapError(err)
	}
	if res == nil || len(*res) == 0 {
		return 0, nil
	}

	first := (*res)[0]
	if first.Error != nil {
		mapped := a.mapError(first.Error)
		if errors.Is(mapped, adapter.ErrNotFound) {
			return 0, nil
		}
		return 0, mapped
	}

	return int64(len(first.Result)), nil
}

// Count returns the number of records matching the given conditions.
func (a *Adapter) Count(ctx context.Context, model string, where []adapter.Condition) (int64, error) {
	sb := strings.Builder{}
	sb.WriteString("SELECT count() FROM ")
	sb.WriteString(model)

	vars := make(map[string]any)
	if len(where) > 0 {
		whereClause, whereVars := buildWhere(model, where)
		sb.WriteString(" WHERE ")
		sb.WriteString(whereClause)
		for k, v := range whereVars {
			vars[k] = v
		}
	}
	sb.WriteString(" GROUP ALL;")

	res, err := query[[]map[string]any](ctx, a, sb.String(), vars)
	if err != nil {
		return 0, a.mapError(err)
	}
	if res == nil || len(*res) == 0 {
		return 0, nil
	}

	first := (*res)[0]
	if first.Error != nil {
		mapped := a.mapError(first.Error)
		if errors.Is(mapped, adapter.ErrNotFound) {
			return 0, nil
		}
		return 0, mapped
	}

	if len(first.Result) == 0 {
		return 0, nil
	}

	rawCount, ok := first.Result[0]["count"]
	if !ok {
		return 0, nil
	}
	return toCountInt64(rawCount), nil
}

// Transaction executes fn atomically within a SurrealDB transaction.
func (a *Adapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	if a.tx != nil {
		// Join existing outer transaction
		return fn(ctx, a)
	}

	if a.db == nil {
		return fmt.Errorf("surrealdb: database connection is nil")
	}

	tx, err := a.db.Begin(ctx)
	if err != nil {
		return a.mapError(err)
	}

	defer func() {
		if !tx.IsClosed() {
			_ = tx.Cancel(ctx)
		}
	}()

	txAdapter := &Adapter{
		db:     a.db,
		tx:     tx,
		schema: a.schema,
	}

	if err := fn(ctx, txAdapter); err != nil {
		_ = tx.Cancel(ctx)
		return a.mapError(err)
	}

	if err := tx.Commit(ctx); err != nil {
		return a.mapError(err)
	}

	return nil
}

func (a *Adapter) mapError(err error) error {
	return MapError(err)
}

func query[T any](ctx context.Context, a *Adapter, sql string, vars map[string]any) (*[]surreal.QueryResult[T], error) {
	if a.tx != nil {
		return surreal.Query[T](ctx, a.tx, sql, vars)
	}
	if a.db == nil {
		return nil, fmt.Errorf("surrealdb: database connection is nil")
	}
	return surreal.Query[T](ctx, a.db, sql, vars)
}

func createRecord[T any, TWhat surreal.TableOrRecord](ctx context.Context, a *Adapter, what TWhat, data any) (*T, error) {
	if a.tx != nil {
		return surreal.Create[T](ctx, a.tx, what, data)
	}
	if a.db == nil {
		return nil, fmt.Errorf("surrealdb: database connection is nil")
	}
	return surreal.Create[T](ctx, a.db, what, data)
}

func (a *Adapter) preparePayloadValue(model, field string, v any) any {
	if v == nil {
		return nil
	}

	isTimeField := false
	a.mu.RLock()
	if a.schema != nil {
		if m, ok := a.schema.GetModel(model); ok {
			if f, ok := m.GetField(field); ok && f.Type == schema.TypeTime {
				isTimeField = true
			}
		}
	}
	a.mu.RUnlock()

	if !isTimeField && (strings.HasSuffix(field, "_at") || strings.HasSuffix(field, "_time") || field == "expires_at") {
		isTimeField = true
	}

	if isTimeField {
		switch val := v.(type) {
		case string:
			if t, err := time.Parse(time.RFC3339Nano, val); err == nil {
				return models.CustomDateTime{Time: t}
			}
			if t, err := time.Parse(time.RFC3339, val); err == nil {
				return models.CustomDateTime{Time: t}
			}
		case time.Time:
			return models.CustomDateTime{Time: val}
		}
	}

	return v
}
