package sqladapter

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/store/sqltx"
)

// BaseAdapter is the shared SQL adapter engine implementing adapter.Adapter.
type BaseAdapter struct {
	db      *sql.DB
	dialect Dialect
	mu      sync.RWMutex
	schema  *schema.Schema
}

var _ adapter.Adapter = (*BaseAdapter)(nil)
var _ adapter.SchemaExporter = (*BaseAdapter)(nil)

// New creates a new BaseAdapter configured with the provided sql.DB and Dialect.
func New(db *sql.DB, d Dialect) *BaseAdapter {
	return &BaseAdapter{
		db:      db,
		dialect: d,
	}
}

// DB returns the underlying database pool.
func (a *BaseAdapter) DB() *sql.DB {
	return a.db
}

// Dialect returns the active SQL dialect.
func (a *BaseAdapter) Dialect() Dialect {
	return a.dialect
}

// RegisterSchema records the compiled schema into the adapter.
func (a *BaseAdapter) RegisterSchema(ctx context.Context, s *schema.Schema) error {
	if s == nil {
		return fmt.Errorf("schema cannot be nil")
	}
	if err := s.Validate(); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.schema = s.Clone()
	return nil
}

// ExportSchema returns the raw DDL statements for creating all tables and indexes.
func (a *BaseAdapter) ExportSchema(ctx context.Context) ([]string, error) {
	a.mu.RLock()
	s := a.schema
	a.mu.RUnlock()

	if s == nil {
		return nil, fmt.Errorf("sqladapter: cannot export schema: no schema registered")
	}

	models := s.Models()
	names := make([]string, 0, len(models))
	for name := range models {
		names = append(names, name)
	}
	sort.Strings(names)

	var stmts []string
	for _, name := range names {
		m := models[name]
		stmts = append(stmts, a.buildCreateTableDDL(m))

		indexes := make([]schema.Index, len(m.Indexes))
		copy(indexes, m.Indexes)
		sort.Slice(indexes, func(i, j int) bool {
			return indexes[i].Name < indexes[j].Name
		})

		for _, idx := range indexes {
			idxDDL := a.buildCreateIndexDDL(m.TableName, idx)
			if idxDDL != "" {
				stmts = append(stmts, idxDDL)
			}
		}
	}
	return stmts, nil
}

// Migrate applies DDL to create missing tables, columns and indexes based on the compiled schema.
func (a *BaseAdapter) Migrate(ctx context.Context) error {
	stmts, err := a.ExportSchema(ctx)
	if err != nil {
		return fmt.Errorf("cannot migrate: %w", err)
	}

	for _, stmt := range stmts {
		if _, err := a.executor(ctx).ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration failed for statement %q: %w", stmt, err)
		}
	}
	return nil
}

// Create inserts a single record into the database table for the given model.
func (a *BaseAdapter) Create(ctx context.Context, modelName string, data map[string]any) (map[string]any, error) {
	m, err := a.getModel(modelName)
	if err != nil {
		return nil, err
	}

	cols := make([]string, 0, len(data))
	placeholders := make([]string, 0, len(data))
	args := make([]any, 0, len(data))

	argIdx := 1
	for k, v := range data {
		field, ok := m.GetField(k)
		colName := k
		if ok {
			colName = field.EffectiveDBName()
		}
		cols = append(cols, a.dialect.Quote(colName))
		placeholders = append(placeholders, a.dialect.Placeholder(argIdx))
		args = append(args, sanitizeArg(v))
		argIdx++
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		a.dialect.Quote(m.TableName),
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	_, err = a.executor(ctx).ExecContext(ctx, query, args...)
	if err != nil {
		return nil, a.dialect.MapError(err)
	}

	return data, nil
}

// FindOne returns the first record matching the given conditions.
func (a *BaseAdapter) FindOne(ctx context.Context, modelName string, where []adapter.Condition) (map[string]any, error) {
	res, err := a.FindMany(ctx, adapter.Query{
		Model: modelName,
		Where: where,
		Limit: 1,
	})
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, adapter.ErrNotFound
	}
	return res[0], nil
}

// FindMany returns all records matching query conditions.
func (a *BaseAdapter) FindMany(ctx context.Context, q adapter.Query) ([]map[string]any, error) {
	m, err := a.getModel(q.Model)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	sb.WriteString("SELECT * FROM ")
	sb.WriteString(a.dialect.Quote(m.TableName))

	args := make([]any, 0)
	argIdx := 1

	if len(q.Where) > 0 {
		sb.WriteString(" WHERE ")
		whereClauses := make([]string, 0, len(q.Where))
		for _, cond := range q.Where {
			clause, newArgs := a.buildCondition(m, cond, argIdx)
			whereClauses = append(whereClauses, clause)
			args = append(args, newArgs...)
			argIdx += len(newArgs)
		}
		sb.WriteString(strings.Join(whereClauses, " AND "))
	}

	if q.SortBy != "" {
		sb.WriteString(" ORDER BY ")
		field, ok := m.GetField(q.SortBy)
		colName := q.SortBy
		if ok {
			colName = field.EffectiveDBName()
		}
		sb.WriteString(a.dialect.Quote(colName))
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
		sb.WriteString(fmt.Sprintf(" OFFSET %d", q.Offset))
	}

	rows, err := a.executor(ctx).QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, a.dialect.MapError(err)
	}
	defer rows.Close()

	return scanRows(rows)
}

// Update modifies records matching the conditions.
func (a *BaseAdapter) Update(ctx context.Context, modelName string, where []adapter.Condition, update map[string]any) (int64, error) {
	m, err := a.getModel(modelName)
	if err != nil {
		return 0, err
	}

	if len(update) == 0 {
		return 0, nil
	}

	setClauses := make([]string, 0, len(update))
	args := make([]any, 0, len(update)+len(where))
	argIdx := 1

	for k, v := range update {
		field, ok := m.GetField(k)
		colName := k
		if ok {
			colName = field.EffectiveDBName()
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = %s", a.dialect.Quote(colName), a.dialect.Placeholder(argIdx)))
		args = append(args, sanitizeArg(v))
		argIdx++
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("UPDATE %s SET %s", a.dialect.Quote(m.TableName), strings.Join(setClauses, ", ")))

	if len(where) > 0 {
		sb.WriteString(" WHERE ")
		whereClauses := make([]string, 0, len(where))
		for _, cond := range where {
			clause, newArgs := a.buildCondition(m, cond, argIdx)
			whereClauses = append(whereClauses, clause)
			args = append(args, newArgs...)
			argIdx += len(newArgs)
		}
		sb.WriteString(strings.Join(whereClauses, " AND "))
	}

	res, err := a.executor(ctx).ExecContext(ctx, sb.String(), args...)
	if err != nil {
		return 0, a.dialect.MapError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return affected, nil
}

// Delete removes records matching conditions.
func (a *BaseAdapter) Delete(ctx context.Context, modelName string, where []adapter.Condition) (int64, error) {
	m, err := a.getModel(modelName)
	if err != nil {
		return 0, err
	}

	var sb strings.Builder
	sb.WriteString("DELETE FROM ")
	sb.WriteString(a.dialect.Quote(m.TableName))

	args := make([]any, 0, len(where))
	argIdx := 1

	if len(where) > 0 {
		sb.WriteString(" WHERE ")
		whereClauses := make([]string, 0, len(where))
		for _, cond := range where {
			clause, newArgs := a.buildCondition(m, cond, argIdx)
			whereClauses = append(whereClauses, clause)
			args = append(args, newArgs...)
			argIdx += len(newArgs)
		}
		sb.WriteString(strings.Join(whereClauses, " AND "))
	}

	res, err := a.executor(ctx).ExecContext(ctx, sb.String(), args...)
	if err != nil {
		return 0, a.dialect.MapError(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return affected, nil
}

// Count returns the number of matching records.
func (a *BaseAdapter) Count(ctx context.Context, modelName string, where []adapter.Condition) (int64, error) {
	m, err := a.getModel(modelName)
	if err != nil {
		return 0, err
	}

	var sb strings.Builder
	sb.WriteString("SELECT COUNT(*) FROM ")
	sb.WriteString(a.dialect.Quote(m.TableName))

	args := make([]any, 0, len(where))
	argIdx := 1

	if len(where) > 0 {
		sb.WriteString(" WHERE ")
		whereClauses := make([]string, 0, len(where))
		for _, cond := range where {
			clause, newArgs := a.buildCondition(m, cond, argIdx)
			whereClauses = append(whereClauses, clause)
			args = append(args, newArgs...)
			argIdx += len(newArgs)
		}
		sb.WriteString(strings.Join(whereClauses, " AND "))
	}

	var count int64
	err = a.executor(ctx).QueryRowContext(ctx, sb.String(), args...).Scan(&count)
	if err != nil {
		return 0, a.dialect.MapError(err)
	}
	return count, nil
}

// Transaction executes fn atomically using sqltx.
func (a *BaseAdapter) Transaction(ctx context.Context, fn func(ctx context.Context, tx adapter.Adapter) error) error {
	return sqltx.Run(ctx, a.db, nil, func(txCtx context.Context) error {
		return fn(txCtx, a)
	})
}

func (a *BaseAdapter) executor(ctx context.Context) sqltx.DBTX {
	return sqltx.Executor(ctx, a.db)
}

func (a *BaseAdapter) getModel(modelName string) (*schema.Model, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.schema != nil {
		if m, ok := a.schema.GetModel(modelName); ok {
			return m, nil
		}
	}
	// Fallback dynamic model
	return &schema.Model{
		Name:       modelName,
		TableName:  modelName,
		PrimaryKey: "id",
		Fields:     map[string]schema.Field{},
	}, nil
}

func (a *BaseAdapter) buildCondition(m *schema.Model, cond adapter.Condition, startIdx int) (string, []any) {
	field, ok := m.GetField(cond.Field)
	colName := cond.Field
	if ok {
		colName = field.EffectiveDBName()
	}
	quotedCol := a.dialect.Quote(colName)

	switch cond.Operator {
	case adapter.OpIsNull:
		return fmt.Sprintf("%s IS NULL", quotedCol), nil
	case adapter.OpIsNotNull:
		return fmt.Sprintf("%s IS NOT NULL", quotedCol), nil
	case adapter.OpIn:
		var vals []any
		if s, ok := cond.Value.([]any); ok {
			if len(s) == 1 && s[0] != nil && reflect.TypeOf(s[0]).Kind() == reflect.Slice {
				rv := reflect.ValueOf(s[0])
				vals = make([]any, rv.Len())
				for i := 0; i < rv.Len(); i++ {
					vals[i] = rv.Index(i).Interface()
				}
			} else {
				vals = s
			}
		} else if cond.Value != nil && reflect.TypeOf(cond.Value).Kind() == reflect.Slice {
			rv := reflect.ValueOf(cond.Value)
			vals = make([]any, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				vals[i] = rv.Index(i).Interface()
			}
		}

		if len(vals) == 0 {
			return "1 = 0", nil
		}
		placeholders := make([]string, len(vals))
		args := make([]any, len(vals))
		for i, v := range vals {
			placeholders[i] = a.dialect.Placeholder(startIdx + i)
			args[i] = sanitizeArg(v)
		}
		return fmt.Sprintf("%s IN (%s)", quotedCol, strings.Join(placeholders, ", ")), args
	default:
		opStr := string(cond.Operator)
		if opStr == "" {
			opStr = "="
		}
		return fmt.Sprintf("%s %s %s", quotedCol, opStr, a.dialect.Placeholder(startIdx)), []any{sanitizeArg(cond.Value)}
	}
}

func (a *BaseAdapter) buildCreateTableDDL(m *schema.Model) string {
	fieldNames := make([]string, 0, len(m.Fields))
	for fName := range m.Fields {
		if fName != m.PrimaryKey {
			fieldNames = append(fieldNames, fName)
		}
	}
	sort.Strings(fieldNames)

	orderedFields := make([]schema.Field, 0, len(m.Fields))
	if pk, ok := m.Fields[m.PrimaryKey]; ok {
		orderedFields = append(orderedFields, pk)
	}
	for _, fName := range fieldNames {
		orderedFields = append(orderedFields, m.Fields[fName])
	}

	cols := make([]string, 0, len(orderedFields))
	for _, f := range orderedFields {
		sqlType := a.dialect.DataType(f.Type)
		colDef := fmt.Sprintf("%s %s", a.dialect.Quote(f.EffectiveDBName()), sqlType)
		if f.Name == m.PrimaryKey {
			colDef += " PRIMARY KEY"
		}
		if f.Required && f.Name != m.PrimaryKey {
			colDef += " NOT NULL"
		}
		if f.Unique && f.Name != m.PrimaryKey {
			colDef += " UNIQUE"
		}
		if ref := f.References; ref != nil && a.dialect.Name() != "sqlite" {
			targetTable := ref.Model
			if a.schema != nil {
				if tm, ok := a.schema.GetModel(ref.Model); ok {
					targetTable = tm.TableName
				}
			}
			colDef += fmt.Sprintf(" REFERENCES %s(%s)", a.dialect.Quote(targetTable), a.dialect.Quote(ref.Field))
			if ref.OnDelete != "" {
				colDef += " ON DELETE " + ref.OnDelete
			}
		}
		cols = append(cols, colDef)
	}

	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", a.dialect.Quote(m.TableName), strings.Join(cols, ", "))
}

func (a *BaseAdapter) buildCreateIndexDDL(tableName string, idx schema.Index) string {
	quotedCols := make([]string, len(idx.Fields))
	for i, f := range idx.Fields {
		quotedCols[i] = a.dialect.Quote(f)
	}
	uniqueKeyword := ""
	if idx.Unique {
		uniqueKeyword = "UNIQUE "
	}
	return fmt.Sprintf(
		"CREATE %sINDEX IF NOT EXISTS %s ON %s (%s)",
		uniqueKeyword,
		a.dialect.Quote(idx.Name),
		a.dialect.Quote(tableName),
		strings.Join(quotedCols, ", "),
	)
}

func sanitizeArg(v any) any {
	if t, ok := v.(time.Time); ok {
		return t.UTC()
	}
	return v
}

func scanRows(rows *sql.Rows) ([]map[string]any, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]any
	for rows.Next() {
		values := make([]any, len(cols))
		scanArgs := make([]any, len(cols))
		for i := range values {
			scanArgs[i] = &values[i]
		}

		if err := rows.Scan(scanArgs...); err != nil {
			return nil, err
		}

		row := make(map[string]any, len(cols))
		for i, col := range cols {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}
	return results, rows.Err()
}
