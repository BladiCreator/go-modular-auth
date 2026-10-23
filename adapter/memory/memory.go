// Package memory provides an in-memory implementation of adapter.Adapter.
//
// It executes schema-driven generic CRUD operations with indexing and unique constraint
// checking in memory. It is ideal for unit tests, local development, and CI environments.
package memory

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/schema"
)

// Adapter is an in-memory adapter.Adapter implementation.
type Adapter struct {
	txMu   sync.Mutex // serializes transactions and prevents concurrent rollbacks
	mu     sync.RWMutex
	schema *schema.Schema
	tables map[string]map[string]map[string]any // modelName -> primaryKey -> row map
}

var _ adapter.Adapter = (*Adapter)(nil)

// New creates an empty in-memory generic Adapter.
func New() *Adapter {
	return &Adapter{
		tables: make(map[string]map[string]map[string]any),
	}
}

// RegisterSchema registers the compiled schema into the in-memory adapter.
func (a *Adapter) RegisterSchema(ctx context.Context, s *schema.Schema) error {
	if s == nil {
		return fmt.Errorf("schema cannot be nil")
	}
	if err := s.Validate(); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.schema = s.Clone()
	for modelName := range a.schema.Models() {
		if _, ok := a.tables[modelName]; !ok {
			a.tables[modelName] = make(map[string]map[string]any)
		}
	}
	return nil
}

// Create inserts a record into the specified model.
func (a *Adapter) Create(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	m, ok := a.getModel(model)
	if !ok {
		return nil, schema.ErrModelNotFound
	}

	pkField := m.PrimaryKey
	pkVal, ok := data[pkField]
	if !ok || pkVal == nil || fmt.Sprintf("%v", pkVal) == "" {
		return nil, fmt.Errorf("%w: missing primary key %q", adapter.ErrConflict, pkField)
	}
	pkStr := fmt.Sprintf("%v", pkVal)

	table, ok := a.tables[model]
	if !ok {
		table = make(map[string]map[string]any)
		a.tables[model] = table
	}

	// Check primary key conflict
	if _, exists := table[pkStr]; exists {
		return nil, fmt.Errorf("%w: primary key %q already exists in model %q", adapter.ErrConflict, pkStr, model)
	}

	// Check unique constraints defined on fields and indexes
	for fieldName, field := range m.Fields {
		if field.Unique {
			val, hasVal := data[fieldName]
			if hasVal && val != nil {
				for _, existing := range table {
					if existingVal, exOk := existing[fieldName]; exOk && matchEqual(existingVal, val) {
						return nil, fmt.Errorf("%w: unique constraint violation on %s.%s", adapter.ErrConflict, model, fieldName)
					}
				}
			}
		}
	}

	// Check composite unique indexes
	for _, idx := range m.Indexes {
		if idx.Unique {
			for _, existing := range table {
				allMatch := true
				for _, f := range idx.Fields {
					v1, ok1 := data[f]
					v2, ok2 := existing[f]
					if !ok1 || !ok2 || !matchEqual(v1, v2) {
						allMatch = false
						break
					}
				}
				if allMatch {
					return nil, fmt.Errorf("%w: unique index violation on %s (%s)", adapter.ErrConflict, model, idx.Name)
				}
			}
		}
	}

	row := maps.Clone(data)
	table[pkStr] = row
	return maps.Clone(row), nil
}

// FindOne returns the first record matching all given conditions.
func (a *Adapter) FindOne(ctx context.Context, model string, where []adapter.Condition) (map[string]any, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	table, ok := a.tables[model]
	if !ok {
		return nil, adapter.ErrNotFound
	}

	for _, row := range table {
		if matchConditions(row, where) {
			return maps.Clone(row), nil
		}
	}

	return nil, adapter.ErrNotFound
}

// FindMany returns all records matching query conditions, supporting sorting and pagination.
func (a *Adapter) FindMany(ctx context.Context, q adapter.Query) ([]map[string]any, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	table, ok := a.tables[q.Model]
	if !ok {
		return []map[string]any{}, nil
	}

	var results []map[string]any
	for _, row := range table {
		if matchConditions(row, q.Where) {
			results = append(results, maps.Clone(row))
		}
	}

	// Sorting
	if q.SortBy != "" {
		slices.SortFunc(results, func(i, j map[string]any) int {
			vi := fmt.Sprintf("%v", i[q.SortBy])
			vj := fmt.Sprintf("%v", j[q.SortBy])
			cmpVal := cmp.Compare(vi, vj)
			if q.Desc {
				return -cmpVal
			}
			return cmpVal
		})
	}

	// Offset
	if q.Offset > 0 {
		if q.Offset >= len(results) {
			return []map[string]any{}, nil
		}
		results = results[q.Offset:]
	}

	// Limit
	if q.Limit > 0 && q.Limit < len(results) {
		results = results[:q.Limit]
	}

	return results, nil
}

// Update modifies matching records in place.
func (a *Adapter) Update(ctx context.Context, model string, where []adapter.Condition, update map[string]any) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	table, ok := a.tables[model]
	if !ok {
		return 0, nil
	}

	var count int64
	for _, row := range table {
		if matchConditions(row, where) {
			for k, v := range update {
				row[k] = v
			}
			count++
		}
	}

	return count, nil
}

// Delete removes matching records.
func (a *Adapter) Delete(ctx context.Context, model string, where []adapter.Condition) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	table, ok := a.tables[model]
	if !ok {
		return 0, nil
	}

	var toDelete []string
	for pk, row := range table {
		if matchConditions(row, where) {
			toDelete = append(toDelete, pk)
		}
	}

	for _, pk := range toDelete {
		delete(table, pk)
	}

	return int64(len(toDelete)), nil
}

// Count returns the number of records matching the conditions.
func (a *Adapter) Count(ctx context.Context, model string, where []adapter.Condition) (int64, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	table, ok := a.tables[model]
	if !ok {
		return 0, nil
	}

	var count int64
	for _, row := range table {
		if matchConditions(row, where) {
			count++
		}
	}
	return count, nil
}

func (a *Adapter) cloneTables() map[string]map[string]map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()

	cloned := make(map[string]map[string]map[string]any, len(a.tables))
	for m, table := range a.tables {
		clonedTable := make(map[string]map[string]any, len(table))
		for pk, row := range table {
			clonedTable[pk] = maps.Clone(row)
		}
		cloned[m] = clonedTable
	}
	return cloned
}

type txCtxKey struct{}

// Transaction executes fn atomically, rolling back if fn returns an error.
// Nested transactions join the parent transaction.
func (a *Adapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	if inTx, ok := ctx.Value(txCtxKey{}).(bool); ok && inTx {
		return fn(ctx, a)
	}

	a.txMu.Lock()
	defer a.txMu.Unlock()

	snapshot := a.cloneTables()

	txCtx := context.WithValue(ctx, txCtxKey{}, true)
	if err := fn(txCtx, a); err != nil {
		a.mu.Lock()
		a.tables = snapshot
		a.mu.Unlock()
		return err
	}
	return nil
}

func (a *Adapter) getModel(name string) (*schema.Model, bool) {
	if a.schema == nil {
		// If no schema registered yet, return a basic fallback model
		return &schema.Model{Name: name, PrimaryKey: "id", Fields: map[string]schema.Field{}}, true
	}
	return a.schema.GetModel(name)
}

func matchConditions(row map[string]any, where []adapter.Condition) bool {
	for _, cond := range where {
		val, exists := row[cond.Field]
		switch cond.Operator {
		case adapter.OpEq:
			if !exists || !matchEqual(val, cond.Value) {
				return false
			}
		case adapter.OpNe:
			if exists && matchEqual(val, cond.Value) {
				return false
			}
		case adapter.OpIsNull:
			if exists && !isNil(val) {
				return false
			}
		case adapter.OpIsNotNull:
			if !exists || isNil(val) {
				return false
			}
		case adapter.OpLt:
			if !exists || !matchLess(val, cond.Value) {
				return false
			}
		case adapter.OpLte:
			if !exists || (!matchLess(val, cond.Value) && !matchEqual(val, cond.Value)) {
				return false
			}
		case adapter.OpGt:
			if !exists || !matchGreater(val, cond.Value) {
				return false
			}
		case adapter.OpGte:
			if !exists || (!matchGreater(val, cond.Value) && !matchEqual(val, cond.Value)) {
				return false
			}
		case adapter.OpIn:
			sliceVal, isSlice := cond.Value.([]any)
			if !isSlice {
				return false
			}
			matched := false
			for _, item := range sliceVal {
				if matchEqual(val, item) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		default:
			// Fallback string comparison
			if fmt.Sprintf("%v", val) != fmt.Sprintf("%v", cond.Value) {
				return false
			}
		}
	}
	return true
}

func matchEqual(v1, v2 any) bool {
	if isNil(v1) && isNil(v2) {
		return true
	}
	if isNil(v1) || isNil(v2) {
		return false
	}
	if b1, ok1 := v1.([]byte); ok1 {
		if b2, ok2 := v2.([]byte); ok2 {
			return bytes.Equal(b1, b2)
		}
		if s2, ok2 := v2.(string); ok2 {
			return string(b1) == s2 || base64.StdEncoding.EncodeToString(b1) == s2 || base64.RawURLEncoding.EncodeToString(b1) == s2
		}
	}
	if b2, ok2 := v2.([]byte); ok2 {
		if s1, ok1 := v1.(string); ok1 {
			return string(b2) == s1 || base64.StdEncoding.EncodeToString(b2) == s1 || base64.RawURLEncoding.EncodeToString(b2) == s1
		}
	}
	if t1, ok1 := parseTime(v1); ok1 {
		if t2, ok2 := parseTime(v2); ok2 {
			return t1.Equal(t2)
		}
	}
	if n1, ok1 := parseNumber(v1); ok1 {
		if n2, ok2 := parseNumber(v2); ok2 {
			return n1 == n2
		}
	}
	return fmt.Sprintf("%v", v1) == fmt.Sprintf("%v", v2)
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

func parseTime(v any) (time.Time, bool) {
	if t, ok := v.(time.Time); ok {
		return t, true
	}
	if s, ok := v.(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t, true
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func parseNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	default:
		return 0, false
	}
}

func matchLess(v1, v2 any) bool {
	if t1, ok1 := parseTime(v1); ok1 {
		if t2, ok2 := parseTime(v2); ok2 {
			return t1.Before(t2)
		}
	}
	if n1, ok1 := parseNumber(v1); ok1 {
		if n2, ok2 := parseNumber(v2); ok2 {
			return n1 < n2
		}
	}
	return fmt.Sprintf("%v", v1) < fmt.Sprintf("%v", v2)
}

func matchGreater(v1, v2 any) bool {
	if t1, ok1 := parseTime(v1); ok1 {
		if t2, ok2 := parseTime(v2); ok2 {
			return t1.After(t2)
		}
	}
	if n1, ok1 := parseNumber(v1); ok1 {
		if n2, ok2 := parseNumber(v2); ok2 {
			return n1 > n2
		}
	}
	return fmt.Sprintf("%v", v1) > fmt.Sprintf("%v", v2)
}
