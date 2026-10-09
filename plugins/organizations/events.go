package organizations

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Event names emitted by the organizations plugin.
const (
	EventOrganizationCreated  auth.EventName = "organizations.created"
	EventOrganizationUpdated  auth.EventName = "organizations.updated"
	EventOrganizationDeleted  auth.EventName = "organizations.deleted"
	EventOwnershipTransferred auth.EventName = "organizations.ownership_transferred"
	EventMemberAdded          auth.EventName = "organizations.member_added"
	EventMemberUpdated        auth.EventName = "organizations.member_updated"
	EventMemberRemoved        auth.EventName = "organizations.member_removed"
	EventTeamCreated          auth.EventName = "organizations.team_created"
	EventTeamUpdated          auth.EventName = "organizations.team_updated"
	EventTeamDeleted          auth.EventName = "organizations.team_deleted"
	EventTeamMemberAdded      auth.EventName = "organizations.team_member_added"
	EventTeamMemberRemoved    auth.EventName = "organizations.team_member_removed"
	EventInvitationCreated    auth.EventName = "organizations.invitation_created"
	EventInvitationAccepted   auth.EventName = "organizations.invitation_accepted"
	EventInvitationRevoked    auth.EventName = "organizations.invitation_revoked"
)

// OrganizationCreatedPayload describes an organization creation event.
type OrganizationCreatedPayload struct {
	OrganizationID string    `json:"organization_id"`
	Slug           string    `json:"slug"`
	OwnerID        string    `json:"owner_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// OrganizationUpdatedPayload describes an organization modification event.
type OrganizationUpdatedPayload struct {
	OrganizationID string    `json:"organization_id"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// OrganizationDeletedPayload describes an organization deletion event.
type OrganizationDeletedPayload struct {
	OrganizationID string    `json:"organization_id"`
	DeletedAt      time.Time `json:"deleted_at"`
}

// OwnershipTransferredPayload describes an ownership change event.
type OwnershipTransferredPayload struct {
	OrganizationID string `json:"organization_id"`
	OldOwnerID     string `json:"old_owner_id"`
	NewOwnerID     string `json:"new_owner_id"`
}

// MemberAddedPayload describes a member addition event.
type MemberAddedPayload struct {
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
	Role           Role   `json:"role"`
}

// MemberUpdatedPayload describes a member role or status change event.
type MemberUpdatedPayload struct {
	OrganizationID string           `json:"organization_id"`
	UserID         string           `json:"user_id"`
	Role           Role             `json:"role"`
	Status         MembershipStatus `json:"status"`
}

// MemberRemovedPayload describes a member removal event.
type MemberRemovedPayload struct {
	OrganizationID string `json:"organization_id"`
	UserID         string `json:"user_id"`
}

// TeamCreatedPayload describes a team creation event.
type TeamCreatedPayload struct {
	OrganizationID string `json:"organization_id"`
	TeamID         string `json:"team_id"`
	Slug           string `json:"slug"`
}

// TeamUpdatedPayload describes a team update event.
type TeamUpdatedPayload struct {
	OrganizationID string `json:"organization_id"`
	TeamID         string `json:"team_id"`
}

// TeamDeletedPayload describes a team deletion event.
type TeamDeletedPayload struct {
	OrganizationID string `json:"organization_id"`
	TeamID         string `json:"team_id"`
}

// TeamMemberPayload describes adding or removing a member from a team.
type TeamMemberPayload struct {
	OrganizationID string `json:"organization_id"`
	TeamID         string `json:"team_id"`
	UserID         string `json:"user_id"`
}

// InvitationCreatedPayload describes an invitation creation event.
type InvitationCreatedPayload struct {
	OrganizationID string    `json:"organization_id"`
	InvitationID   string    `json:"invitation_id"`
	Email          string    `json:"email"`
	Role           Role      `json:"role"`
	InviterUserID  string    `json:"inviter_user_id"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// InvitationAcceptedPayload describes an invitation redemption event.
type InvitationAcceptedPayload struct {
	OrganizationID string    `json:"organization_id"`
	InvitationID   string    `json:"invitation_id"`
	UserID         string    `json:"user_id"`
	AcceptedAt     time.Time `json:"accepted_at"`
}

// InvitationRevokedPayload describes an invitation revocation event.
type InvitationRevokedPayload struct {
	OrganizationID string `json:"organization_id"`
	InvitationID   string `json:"invitation_id"`
}
