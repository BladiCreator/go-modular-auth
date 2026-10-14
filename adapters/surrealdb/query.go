package surrealdb

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

func buildWhere(model string, conditions []adapter.Condition) (string, map[string]any) {
	if len(conditions) == 0 {
		return "", nil
	}

	clauses := make([]string, 0, len(conditions))
	vars := make(map[string]any, len(conditions))

	for i, cond := range conditions {
		paramName := fmt.Sprintf("p_%d", i)
		col := quoteField(cond.Field)

		switch cond.Operator {
		case adapter.OpIsNull:
			clauses = append(clauses, fmt.Sprintf("(%s IS NULL OR %s IS NONE)", col, col))
		case adapter.OpIsNotNull:
			clauses = append(clauses, fmt.Sprintf("(%s != NULL AND %s != NONE)", col, col))
		case adapter.OpIn:
			val := cond.Value
			if cond.Field == "id" {
				val = toRecordIDSlice(model, cond.Value)
			}
			vars[paramName] = val
			clauses = append(clauses, fmt.Sprintf("%s IN $%s", col, paramName))
		case adapter.OpLike:
			vars[paramName] = cond.Value
			clauses = append(clauses, fmt.Sprintf("%s ~ $%s", col, paramName))
		default:
			val := cond.Value
			if cond.Field == "id" {
				val = toRecordID(model, cond.Value)
			}
			vars[paramName] = val
			clauses = append(clauses, fmt.Sprintf("%s %s $%s", col, string(cond.Operator), paramName))
		}
	}

	return strings.Join(clauses, " AND "), vars
}

func quoteField(f string) string {
	if strings.Contains(f, ".") || strings.Contains(f, "->") || strings.HasPrefix(f, "`") {
		return f
	}
	return "`" + f + "`"
}

func toRecordID(table string, val any) any {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case models.RecordID:
		return v
	case *models.RecordID:
		if v == nil {
			return nil
		}
		return *v
	case string:
		if strings.Contains(v, ":") {
			if rec, err := models.ParseRecordID(v); err == nil {
				return *rec
			}
		}
		return models.NewRecordID(table, v)
	default:
		return models.NewRecordID(table, v)
	}
}

func toRecordIDSlice(table string, val any) any {
	if val == nil {
		return nil
	}
	switch slice := val.(type) {
	case []any:
		res := make([]any, len(slice))
		for i, v := range slice {
			res[i] = toRecordID(table, v)
		}
		return res
	case []string:
		res := make([]any, len(slice))
		for i, v := range slice {
			res[i] = toRecordID(table, v)
		}
		return res
	default:
		return val
	}
}

func normalizeRow(model string, row map[string]any) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		if k == "id" {
			out[k] = normalizeID(model, v)
		} else {
			out[k] = normalizeValue(v)
		}
	}
	return out
}

func normalizeID(model string, v any) any {
	if v == nil {
		return nil
	}
	switch id := v.(type) {
	case models.RecordID:
		return fmt.Sprintf("%v", id.ID)
	case *models.RecordID:
		if id == nil {
			return nil
		}
		return fmt.Sprintf("%v", id.ID)
	case string:
		prefix := model + ":"
		if strings.HasPrefix(id, prefix) {
			return strings.TrimPrefix(id, prefix)
		}
		return id
	default:
		return fmt.Sprintf("%v", v)
	}
}

func normalizeValue(v any) any {
	switch val := v.(type) {
	case models.RecordID:
		return val.String()
	case *models.RecordID:
		if val == nil {
			return nil
		}
		return val.String()
	default:
		return v
	}
}

func toCountInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case uint64:
		return int64(n)
	case uint32:
		return int64(n)
	case uint:
		return int64(n)
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		var i int64
		_, _ = fmt.Sscanf(n, "%d", &i)
		return i
	default:
		return 0
	}
}
