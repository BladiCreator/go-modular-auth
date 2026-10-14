package audit

import (
	"context"
)

// Audit represents the strongly typed public capability provided by the audit plugin.
// Applications retrieve this capability via auth.Get[plugins.Audit]().
type Audit interface {
	// Record manually registers an explicit audit entry, ensuring sanitization before persistence.
	Record(ctx context.Context, record *AuditRecord) error

	// Query searches the audit log with customizable filtering and pagination criteria.
	Query(ctx context.Context, filter ListFilter) (*ListResult, error)

	// GetByID retrieves a single audit entry by its unique identifier.
	GetByID(ctx context.Context, id string) (*AuditRecord, error)

	// QueryByActor returns audit entries performed by or associated with a specific actor subject.
	QueryByActor(ctx context.Context, subject string, limit int) ([]*AuditRecord, error)

	// QueryByTarget returns audit entries affecting a specific target resource type and identifier.
	QueryByTarget(ctx context.Context, targetType, targetID string, limit int) ([]*AuditRecord, error)

	// QueryByOrganization returns paginated audit records scoped to a multi-tenant organization.
	QueryByOrganization(ctx context.Context, orgID string, filter ListFilter) (*ListResult, error)
}
