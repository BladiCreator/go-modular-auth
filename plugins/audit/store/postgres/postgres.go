// Package postgres implements store.Store using PostgreSQL database/sql.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/BladiCreator/go-modular-auth-audit/store"
)

// Store implements store.Store on PostgreSQL.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New returns an initialized PostgreSQL audit store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

type txKey struct{}

func (s *Store) getExecutor(ctx context.Context) executor {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Record persists a single immutable audit log record.
func (s *Store) Record(ctx context.Context, record *store.AuditRecord) error {
	if record == nil {
		return store.ErrNilRecord
	}

	if err := record.Validate(); err != nil {
		return err
	}

	metaJSON, err := json.Marshal(record.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO auth_audit_records (
			id, timestamp, event, action, actor_subject, actor_type,
			target_type, target_id, outcome, organization_id,
			ip_address, user_agent, metadata, error_message
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);
	`

	_, err = s.getExecutor(ctx).ExecContext(ctx, query,
		record.ID, record.Timestamp, record.Event, record.Action,
		record.ActorSubject, record.ActorType, record.TargetType, record.TargetID,
		string(record.Outcome), record.OrganizationID, record.IPAddress, record.UserAgent,
		string(metaJSON), record.ErrorMessage,
	)
	return err
}

// RecordBatch persists multiple audit records in a single transaction.
func (s *Store) RecordBatch(ctx context.Context, records []*store.AuditRecord) error {
	if len(records) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO auth_audit_records (
			id, timestamp, event, action, actor_subject, actor_type,
			target_type, target_id, outcome, organization_id,
			ip_address, user_agent, metadata, error_message
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, record := range records {
		if record == nil {
			return store.ErrNilRecord
		}
		if err := record.Validate(); err != nil {
			return err
		}

		metaJSON, err := json.Marshal(record.Metadata)
		if err != nil {
			metaJSON = []byte("{}")
		}

		_, err = stmt.ExecContext(ctx,
			record.ID, record.Timestamp, record.Event, record.Action,
			record.ActorSubject, record.ActorType, record.TargetType, record.TargetID,
			string(record.Outcome), record.OrganizationID, record.IPAddress, record.UserAgent,
			string(metaJSON), record.ErrorMessage,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetByID retrieves a single audit record by primary ID.
func (s *Store) GetByID(ctx context.Context, id string) (*store.AuditRecord, error) {
	query := `
		SELECT id, timestamp, event, action, actor_subject, actor_type,
		       target_type, target_id, outcome, organization_id,
		       ip_address, user_agent, metadata, error_message
		FROM auth_audit_records
		WHERE id = $1
		LIMIT 1;
	`

	var rec store.AuditRecord
	var outcomeStr string
	var metaStr string

	err := s.getExecutor(ctx).QueryRowContext(ctx, query, id).Scan(
		&rec.ID, &rec.Timestamp, &rec.Event, &rec.Action,
		&rec.ActorSubject, &rec.ActorType, &rec.TargetType, &rec.TargetID,
		&outcomeStr, &rec.OrganizationID, &rec.IPAddress, &rec.UserAgent,
		&metaStr, &rec.ErrorMessage,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}

	rec.Outcome = store.Outcome(outcomeStr)
	if err := json.Unmarshal([]byte(metaStr), &rec.Metadata); err != nil {
		rec.Metadata = make(map[string]any)
	}

	return &rec, nil
}

// Query filters and paginates audit records matching ListFilter.
func (s *Store) Query(ctx context.Context, filter store.ListFilter) ([]*store.AuditRecord, int, error) {
	filter.Normalize()

	var conditions []string
	var args []any
	argIdx := 1

	if filter.ActorSubject != "" {
		conditions = append(conditions, fmt.Sprintf("actor_subject = $%d", argIdx))
		args = append(args, filter.ActorSubject)
		argIdx++
	}
	if filter.ActorType != "" {
		conditions = append(conditions, fmt.Sprintf("actor_type = $%d", argIdx))
		args = append(args, filter.ActorType)
		argIdx++
	}
	if filter.TargetType != "" {
		conditions = append(conditions, fmt.Sprintf("target_type = $%d", argIdx))
		args = append(args, filter.TargetType)
		argIdx++
	}
	if filter.TargetID != "" {
		conditions = append(conditions, fmt.Sprintf("target_id = $%d", argIdx))
		args = append(args, filter.TargetID)
		argIdx++
	}
	if filter.Event != "" {
		conditions = append(conditions, fmt.Sprintf("event = $%d", argIdx))
		args = append(args, filter.Event)
		argIdx++
	}
	if filter.Outcome != "" {
		conditions = append(conditions, fmt.Sprintf("outcome = $%d", argIdx))
		args = append(args, string(filter.Outcome))
		argIdx++
	}
	if filter.OrganizationID != "" {
		conditions = append(conditions, fmt.Sprintf("organization_id = $%d", argIdx))
		args = append(args, filter.OrganizationID)
		argIdx++
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, filter.Since)
		argIdx++
	}
	if !filter.Until.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, filter.Until)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM auth_audit_records %s;", whereClause)
	var total int
	if err := s.getExecutor(ctx).QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	dataQuery := fmt.Sprintf(`
		SELECT id, timestamp, event, action, actor_subject, actor_type,
		       target_type, target_id, outcome, organization_id,
		       ip_address, user_agent, metadata, error_message
		FROM auth_audit_records
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d;
	`, whereClause, argIdx, argIdx+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := s.getExecutor(ctx).QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	records := make([]*store.AuditRecord, 0)
	for rows.Next() {
		var rec store.AuditRecord
		var outcomeStr string
		var metaStr string

		if err := rows.Scan(
			&rec.ID, &rec.Timestamp, &rec.Event, &rec.Action,
			&rec.ActorSubject, &rec.ActorType, &rec.TargetType, &rec.TargetID,
			&outcomeStr, &rec.OrganizationID, &rec.IPAddress, &rec.UserAgent,
			&metaStr, &rec.ErrorMessage,
		); err != nil {
			return nil, 0, err
		}

		rec.Outcome = store.Outcome(outcomeStr)
		if err := json.Unmarshal([]byte(metaStr), &rec.Metadata); err != nil {
			rec.Metadata = make(map[string]any)
		}

		records = append(records, &rec)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return records, total, nil
}
