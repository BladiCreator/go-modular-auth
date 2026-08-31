package organization

import (
	"context"
)

// OrgRepository defines the persistence operations for organization tenant boundaries.
type OrgRepository interface {
	// CreateOrganization persists a new organization tenant boundary in storage.
	CreateOrganization(ctx context.Context, org *Organization) error

	// GetOrganizationByID retrieves an organization record by its unique ID.
	GetOrganizationByID(ctx context.Context, id string) (*Organization, error)

	// GetOrganizationBySlug retrieves an organization record by its unique URL slug.
	GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)

	// UpdateOrganization updates mutable fields of an organization.
	UpdateOrganization(ctx context.Context, org *Organization) error

	// DeleteOrganization permanently removes an organization record and cascades related data.
	DeleteOrganization(ctx context.Context, id string) error

	// ListOrganizationsByUserID retrieves all organizations in which a user holds active membership.
	ListOrganizationsByUserID(ctx context.Context, userID string) ([]*Organization, error)
}
