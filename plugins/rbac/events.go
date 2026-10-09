package rbac

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	EventRoleCreated     auth.EventName = "rbac.role.created"
	EventRoleUpdated     auth.EventName = "rbac.role.updated"
	EventRoleDeleted     auth.EventName = "rbac.role.deleted"
	EventRoleAssigned    auth.EventName = "rbac.role.assigned"
	EventRoleRevoked     auth.EventName = "rbac.role.revoked"
	EventAccessEvaluated auth.EventName = "rbac.access.evaluated"
)

// RoleCreatedPayload is emitted when a new role is defined.
type RoleCreatedPayload struct {
	RoleID    string    `json:"role_id"`
	Name      string    `json:"name"`
	Scope     Scope     `json:"scope"`
	Timestamp time.Time `json:"timestamp"`
}

// RoleUpdatedPayload is emitted when a role definition is updated.
type RoleUpdatedPayload struct {
	RoleID    string    `json:"role_id"`
	Name      string    `json:"name"`
	Scope     Scope     `json:"scope"`
	Timestamp time.Time `json:"timestamp"`
}

// RoleDeletedPayload is emitted when a role is removed.
type RoleDeletedPayload struct {
	RoleID    string    `json:"role_id"`
	Timestamp time.Time `json:"timestamp"`
}

// RoleAssignedPayload is emitted when a role is assigned to a principal.
type RoleAssignedPayload struct {
	AssignmentID     string             `json:"assignment_id"`
	RoleID           string             `json:"role_id"`
	PrincipalSubject string             `json:"principal_subject"`
	PrincipalType    auth.PrincipalType `json:"principal_type"`
	Scope            Scope              `json:"scope"`
	ScopeID          string             `json:"scope_id,omitempty"`
	Timestamp        time.Time          `json:"timestamp"`
}

// RoleRevokedPayload is emitted when a role assignment is revoked.
type RoleRevokedPayload struct {
	AssignmentID     string    `json:"assignment_id"`
	RoleID           string    `json:"role_id"`
	PrincipalSubject string    `json:"principal_subject"`
	Timestamp        time.Time `json:"timestamp"`
}

// AccessEvaluatedPayload is emitted when an authorization decision is evaluated.
type AccessEvaluatedPayload struct {
	PrincipalSubject string             `json:"principal_subject"`
	PrincipalType    auth.PrincipalType `json:"principal_type"`
	Permission       string             `json:"permission"`
	Allowed          bool               `json:"allowed"`
	MatchedRole      string             `json:"matched_role,omitempty"`
	ResourceType     string             `json:"resource_type,omitempty"`
	ResourceID       string             `json:"resource_id,omitempty"`
	OrganizationID   string             `json:"organization_id,omitempty"`
	ServiceID        string             `json:"service_id,omitempty"`
	Timestamp        time.Time          `json:"timestamp"`
}
