package organization

import (
	"context"
)

// InvitationRepository defines the persistence operations for organization invitations.
type InvitationRepository interface {
	// CreateInvitation persists a new email invitation to join an organization.
	CreateInvitation(ctx context.Context, invitation *Invitation) error

	// GetInvitationByID retrieves an invitation record by ID.
	GetInvitationByID(ctx context.Context, id string) (*Invitation, error)

	// GetPendingInvitation retrieves an active pending invitation by organization ID and email.
	GetPendingInvitation(ctx context.Context, orgID, email string) (*Invitation, error)

	// UpdateInvitation updates the status (e.g. accepted, revoked, expired) of an invitation.
	UpdateInvitation(ctx context.Context, invitation *Invitation) error

	// DeleteInvitation removes an invitation record from storage.
	DeleteInvitation(ctx context.Context, id string) error

	// ListInvitationsByOrgID lists invitations for an organization, optionally filtered by status.
	ListInvitationsByOrgID(ctx context.Context, orgID string, status *InvitationStatus) ([]*Invitation, error)

	// ListInvitationsByEmail lists invitations sent to a user's email across all organizations.
	ListInvitationsByEmail(ctx context.Context, email string, status *InvitationStatus) ([]*Invitation, error)

	// CountPendingInvitations returns the count of active pending invitations for an org.
	CountPendingInvitations(ctx context.Context, orgID string) (int, error)
}
