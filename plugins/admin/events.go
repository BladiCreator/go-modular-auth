package admin

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Administrative audit event identifiers emitted to GoModularAuth's EventBus.
const (
	EventUserDisabled           auth.EventName = "admin.user.disabled"
	EventUserEnabled            auth.EventName = "admin.user.enabled"
	EventUserDeleted            auth.EventName = "admin.user.deleted"
	EventSessionRevoked         auth.EventName = "admin.session.revoked"
	EventPasswordResetInitiated auth.EventName = "admin.password_reset.initiated"
	EventEmailVerified          auth.EventName = "admin.email.verified"
	EventAdminRoleAssigned      auth.EventName = "admin.role.assigned"
)

// UserDisabledPayload describes a user disable audit event.
type UserDisabledPayload struct {
	ActorID      string    `json:"actor_id"`
	TargetUserID string    `json:"target_user_id"`
	Reason       string    `json:"reason"`
	DisabledAt   time.Time `json:"disabled_at"`
}

// UserEnabledPayload describes a user enable audit event.
type UserEnabledPayload struct {
	ActorID      string    `json:"actor_id"`
	TargetUserID string    `json:"target_user_id"`
	EnabledAt    time.Time `json:"enabled_at"`
}

// UserDeletedPayload describes a user deletion audit event.
type UserDeletedPayload struct {
	ActorID      string    `json:"actor_id"`
	TargetUserID string    `json:"target_user_id"`
	DeletedAt    time.Time `json:"deleted_at"`
}

// SessionRevokedPayload describes a session revocation audit event.
type SessionRevokedPayload struct {
	ActorID      string    `json:"actor_id"`
	TargetUserID string    `json:"target_user_id"`
	RevokedAt    time.Time `json:"revoked_at"`
}

// PasswordResetInitiatedPayload describes an administrative password reset initiation.
// CRITICAL: NEVER includes reset tokens or secret material in the event payload.
type PasswordResetInitiatedPayload struct {
	ActorID      string    `json:"actor_id"`
	TargetUserID string    `json:"target_user_id"`
	InitiatedAt  time.Time `json:"initiated_at"`
}

// EmailVerifiedPayload describes an administrative email verification override.
type EmailVerifiedPayload struct {
	ActorID      string    `json:"actor_id"`
	TargetUserID string    `json:"target_user_id"`
	VerifiedAt   time.Time `json:"verified_at"`
}

// AdminRoleAssignedPayload describes an administrative privilege assignment audit event.
type AdminRoleAssignedPayload struct {
	ActorID      string    `json:"actor_id"`
	TargetUserID string    `json:"target_user_id"`
	IsAdmin      bool      `json:"is_admin"`
	Role         string    `json:"role"`
	AssignedAt   time.Time `json:"assigned_at"`
}
