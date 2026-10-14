package audit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/schema"
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

func generateRecordID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "aud_" + hex.EncodeToString(b), nil
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

const (
	ModelAuditRecords = "audit_records"
)

// RegisterSchema registers the audit_records model in the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelAuditRecords, ModelAuditRecords, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "timestamp", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "event", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "action", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "actor_subject", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "actor_type", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "target_type", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "target_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "outcome", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "organization_id", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "ip_address", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "user_agent", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "error_message", Type: schema.TypeString})
	m.Indexes = []schema.Index{
		{Name: "idx_audit_records_timestamp", Fields: []string{"timestamp"}},
		{Name: "idx_audit_records_actor", Fields: []string{"actor_subject"}},
		{Name: "idx_audit_records_target", Fields: []string{"target_type", "target_id"}},
		{Name: "idx_audit_records_event", Fields: []string{"event"}},
		{Name: "idx_audit_records_org", Fields: []string{"organization_id"}},
	}
	return s.AddModel(m)
}
