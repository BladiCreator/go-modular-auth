package surrealdb

import (
	"context"
	"fmt"
	"strings"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// RegisterSchema validates and registers the compiled schema into the adapter.
func (a *Adapter) RegisterSchema(ctx context.Context, s *schema.Schema) error {
	if s == nil {
		return fmt.Errorf("surrealdb: schema cannot be nil")
	}
	if err := s.Validate(); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.schema = s.Clone()
	return nil
}

// Migrate applies SurrealQL DDL definitions for tables, fields, and indexes based on the registered schema.
func (a *Adapter) Migrate(ctx context.Context) error {
	a.mu.RLock()
	s := a.schema
	a.mu.RUnlock()

	if s == nil {
		return fmt.Errorf("surrealdb: cannot migrate without a registered schema")
	}

	for _, m := range s.Models() {
		ddls := a.buildModelDDL(m)
		for _, stmt := range ddls {
			if _, err := query[any](ctx, a, stmt, nil); err != nil {
				return fmt.Errorf("surrealdb: migration failed on statement %q: %w", stmt, a.mapError(err))
			}
		}
	}

	return nil
}

func (a *Adapter) buildModelDDL(m *schema.Model) []string {
	table := m.TableName
	if table == "" {
		table = m.Name
	}

	var stmts []string
	// Define table as SCHEMALESS to support dynamic plugin extension fields while enforcing declared indexes
	stmts = append(stmts, fmt.Sprintf("DEFINE TABLE IF NOT EXISTS %s SCHEMALESS;", table))

	for _, f := range m.Fields {
		dbName := f.EffectiveDBName()
		if dbName == "id" {
			continue
		}

		surrealType := mapSurrealType(f.Type)
		stmts = append(stmts, fmt.Sprintf("DEFINE FIELD IF NOT EXISTS %s ON TABLE %s TYPE %s;", quoteField(dbName), table, surrealType))

		if f.Unique {
			idxName := fmt.Sprintf("idx_%s_%s_unique", table, dbName)
			stmts = append(stmts, fmt.Sprintf("DEFINE INDEX IF NOT EXISTS %s ON TABLE %s FIELDS %s UNIQUE;", idxName, table, quoteField(dbName)))
		}
	}

	for _, idx := range m.Indexes {
		fields := make([]string, len(idx.Fields))
		for i, fieldName := range idx.Fields {
			col := fieldName
			if f, ok := m.GetField(fieldName); ok {
				col = f.EffectiveDBName()
			}
			fields[i] = quoteField(col)
		}

		uniqueClause := ""
		if idx.Unique {
			uniqueClause = " UNIQUE"
		}
		stmts = append(stmts, fmt.Sprintf("DEFINE INDEX IF NOT EXISTS %s ON TABLE %s FIELDS %s%s;", idx.Name, table, strings.Join(fields, ", "), uniqueClause))
	}

	return stmts
}

func mapSurrealType(dt schema.DataType) string {
	switch dt {
	case schema.TypeString:
		return "string"
	case schema.TypeInt64:
		return "int"
	case schema.TypeFloat64:
		return "float"
	case schema.TypeBool:
		return "bool"
	case schema.TypeTime:
		return "datetime"
	case schema.TypeBytes:
		return "bytes"
	case schema.TypeJSON:
		return "any"
	default:
		return "any"
	}
}
