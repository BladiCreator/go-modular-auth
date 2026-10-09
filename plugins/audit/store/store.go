// Package store defines the persistence contract for security audit records in GoModularAuth.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

var (
	// ErrNotFound indicates that the requested audit record does not exist in storage.
	ErrNotFound = errors.New("audit store: record not found")

	// ErrNilRecord indicates that a nil audit record was passed to storage.
	ErrNilRecord = errors.New("audit store: record cannot be nil")

	// ErrEventRequired indicates an attempt to write an audit record with an empty event identifier.
	ErrEventRequired = errors.New("audit store: event identifier cannot be empty")
)

// Outcome classifies the result of an audited operation.
type Outcome string

const (
	// OutcomeSuccess denotes an operation that completed successfully.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure denotes an operation that failed, was rejected, or unauthorized.
	OutcomeFailure Outcome = "failure"
	// OutcomeUnknown denotes an operation whose explicit result was indeterminate.
	OutcomeUnknown Outcome = "unknown"
)

// TargetResource specifies the subject or resource affected by an audited event.
type TargetResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Actor encapsulates the security principal initiating or associated with the audited action.
type Actor struct {
	Subject   string             `json:"subject"`
	Type      auth.PrincipalType `json:"type"`
	IPAddress string             `json:"ip_address,omitempty"`
	UserAgent string             `json:"user_agent,omitempty"`
}

// AuditRecord represents an immutable audit log entry capturing a security-relevant event.
// It complies strictly with enterprise audit standards, ensuring no secrets, tokens,
// hashes or OTPs are persisted in the record.
type AuditRecord struct {
	ID             string         `json:"id"`
	Timestamp      time.Time      `json:"timestamp"`
	Event          string         `json:"event"`
	Action         string         `json:"action"`
	ActorSubject   string         `json:"actor_subject"`
	ActorType      string         `json:"actor_type"`
	TargetType     string         `json:"target_type"`
	TargetID       string         `json:"target_id"`
	Outcome        Outcome        `json:"outcome"`
	OrganizationID string         `json:"organization_id,omitempty"`
	IPAddress      string         `json:"ip_address,omitempty"`
	UserAgent      string         `json:"user_agent,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	ErrorMessage   string         `json:"error_message,omitempty"`
}

// Validate ensures all mandatory audit record fields are populated and sets defaults.
func (r *AuditRecord) Validate() error {
	if r.ID == "" {
		id, err := generateRecordID()
		if err != nil {
			return fmt.Errorf("failed to generate audit record id: %w", err)
		}
		r.ID = id
	}

	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}

	if r.Event == "" {
		return ErrEventRequired
	}

	if r.Action == "" {
		r.Action = r.Event
	}

	if r.Outcome == "" {
		r.Outcome = OutcomeSuccess
	}

	if r.Metadata == nil {
		r.Metadata = make(map[string]any)
	}

	return nil
}

// ListFilter defines search and pagination parameters for querying audit records.
type ListFilter struct {
	ActorSubject   string    `json:"actor_subject,omitempty"`
	ActorType      string    `json:"actor_type,omitempty"`
	TargetType     string    `json:"target_type,omitempty"`
	TargetID       string    `json:"target_id,omitempty"`
	Event          string    `json:"event,omitempty"`
	Outcome        Outcome   `json:"outcome,omitempty"`
	OrganizationID string    `json:"organization_id,omitempty"`
	Since          time.Time `json:"since,omitempty"`
	Until          time.Time `json:"until,omitempty"`
	Limit          int       `json:"limit,omitempty"`
	Offset         int       `json:"offset,omitempty"`
}

// Normalize validates and applies reasonable defaults to filter parameters.
func (f *ListFilter) Normalize() {
	if f.Limit <= 0 {
		f.Limit = 50
	} else if f.Limit > 500 {
		f.Limit = 500
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
}

// ListResult wraps the matching audit entries and total count for pagination.
type ListResult struct {
	Records []*AuditRecord `json:"records"`
	Total   int            `json:"total"`
	Limit   int            `json:"limit"`
	Offset  int            `json:"offset"`
}

func generateRecordID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "aud_" + hex.EncodeToString(b), nil
}

// Store defines the persistent storage contract required by the audit plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormAuditStore struct {
//		db *gorm.DB
//	}
//
//	func (s *GormAuditStore) Record(ctx context.Context, record *store.AuditRecord) error {
//		if record == nil {
//			return store.ErrNilRecord
//		}
//		return s.db.WithContext(ctx).Create(record).Error
//	}
//
// # Storage and Immutability Guarantee:
//
// Audit records represent an append-only, tamper-evident security ledger.
// In compliance with enterprise compliance standards (SOC 2, ISO 27001, HIPAA),
// implementations must never support UPDATE or DELETE operations on audit entries.
// For high-throughput environments, records may be buffered and flushed in batches
// or persisted directly to an indexed relational database table.
type Store interface {
	// Record persists a single immutable audit log record.
	//
	// Function:
	//   Invoked synchronously or asynchronously whenever a security-relevant event occurs.
	//
	// Storage:
	//   Database (GORM / SQL) - Append-only write.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - record: Structured audit record to persist.
	//
	// Returns:
	//   - error: ErrNilRecord if record is nil, or infrastructure error.
	//
	// Example SQL:
	//   INSERT INTO auth_audit_records (id, timestamp, event, action, actor_subject, actor_type, target_type, target_id, outcome, organization_id, ip_address, user_agent, metadata, error_message) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);
	Record(ctx context.Context, record *AuditRecord) error

	// RecordBatch persists multiple audit records atomically or in a single batch operation.
	//
	// Function:
	//   Invoked by asynchronous worker queues to flush batched audit events efficiently.
	//
	// Storage:
	//   Database (GORM / SQL) - Multi-row batch insert.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - records: Slice of structured audit records to persist.
	//
	// Returns:
	//   - error: Infrastructure error if batch insertion fails.
	//
	// Example SQL:
	//   INSERT INTO auth_audit_records (id, timestamp, event, action, actor_subject, actor_type, target_type, target_id, outcome, organization_id, ip_address, user_agent, metadata, error_message) VALUES ($1, $2, ...), ($15, $16, ...);
	RecordBatch(ctx context.Context, records []*AuditRecord) error

	// GetByID retrieves a specific audit record by its unique identifier.
	//
	// Function:
	//   Invoked during security investigations or forensic detail views.
	//
	// Storage:
	//   Database (GORM / SQL) - Primary key lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Unique audit record identifier.
	//
	// Returns:
	//   - *store.AuditRecord: Found record.
	//   - error: ErrNotFound if missing, or infrastructure error.
	//
	// Example SQL:
	//   SELECT id, timestamp, event, action, actor_subject, actor_type, target_type, target_id, outcome, organization_id, ip_address, user_agent, metadata, error_message FROM auth_audit_records WHERE id = $1 LIMIT 1;
	GetByID(ctx context.Context, id string) (*AuditRecord, error)

	// Query retrieves filtered and paginated audit records matching the specified criteria.
	//
	// Function:
	//   Invoked by security administrators, dashboards, SIEM connectors, and compliance audits.
	//
	// Storage:
	//   Database (GORM / SQL) - Indexed query with ordering and pagination.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - filter: Filter and pagination criteria.
	//
	// Returns:
	//   - []*store.AuditRecord: Paginated slice of matching records.
	//   - int: Total count of matching records across all pages.
	//   - error: Infrastructure error if query fails.
	//
	// Example SQL:
	//   SELECT id, timestamp, event, action, actor_subject, actor_type, target_type, target_id, outcome, organization_id, ip_address, user_agent, metadata, error_message FROM auth_audit_records WHERE organization_id = $1 AND timestamp >= $2 ORDER BY timestamp DESC LIMIT $3 OFFSET $4;
	Query(ctx context.Context, filter ListFilter) ([]*AuditRecord, int, error)
}
