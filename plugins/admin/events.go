package admin

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// Event bus topic string constants emitted during administrative lifecycle actions.
const (
	EventUserCreated          = "admin:user:created"
	EventUserUpdated          = "admin:user:updated"
	EventUserDeleted          = "admin:user:deleted"
	EventUserRoleChanged      = "admin:user:role_changed"
	EventUserBanned           = "admin:user:banned"
	EventUserUnbanned         = "admin:user:unbanned"
	EventUserImpersonated     = "admin:user:impersonated"
	EventImpersonationStopped = "admin:user:impersonation_stopped"
	EventUserPasswordChanged  = "admin:user:password_changed"
	EventSessionRevoked       = "admin:session:revoked"
	EventAllSessionsRevoked   = "admin:session:all_revoked"
)

type (
	// UserCreatedEventPayload is dispatched when a new user is provisioned by an administrator.
	UserCreatedEventPayload struct {
		CallerID   string         `json:"caller_id"`
		CallerRole string         `json:"caller_role"`
		User       *entity.User   `json:"user"`
		Extra      map[string]any `json:"extra,omitempty"`
	}

	// UserUpdatedEventPayload is dispatched when an administrator updates a user record.
	UserUpdatedEventPayload struct {
		CallerID   string         `json:"caller_id"`
		CallerRole string         `json:"caller_role"`
		User       *entity.User   `json:"user"`
		Extra      map[string]any `json:"extra,omitempty"`
	}

	// UserDeletedEventPayload is dispatched when a user account is deleted by an administrator.
	UserDeletedEventPayload struct {
		CallerID   string         `json:"caller_id"`
		CallerRole string         `json:"caller_role"`
		UserID     string         `json:"user_id"`
		Extra      map[string]any `json:"extra,omitempty"`
	}

	// UserRoleChangedEventPayload is dispatched when a user's role assignment is modified.
	UserRoleChangedEventPayload struct {
		CallerID   string         `json:"caller_id"`
		CallerRole string         `json:"caller_role"`
		UserID     string         `json:"user_id"`
		OldRole    string         `json:"old_role"`
		NewRole    string         `json:"new_role"`
		User       *entity.User   `json:"user"`
		Extra      map[string]any `json:"extra,omitempty"`
	}

	// UserBannedEventPayload is dispatched when a user account is suspended.
	UserBannedEventPayload struct {
		CallerID   string         `json:"caller_id"`
		CallerRole string         `json:"caller_role"`
		UserID     string         `json:"user_id"`
		BanReason  string         `json:"ban_reason"`
		BanExpires *time.Time     `json:"ban_expires,omitempty"`
		User       *entity.User   `json:"user"`
		Extra      map[string]any `json:"extra,omitempty"`
	}

	// UserUnbannedEventPayload is dispatched when a suspension is lifted from a user.
	UserUnbannedEventPayload struct {
		CallerID   string         `json:"caller_id"`
		CallerRole string         `json:"caller_role"`
		UserID     string         `json:"user_id"`
		User       *entity.User   `json:"user"`
		Extra      map[string]any `json:"extra,omitempty"`
	}

	// UserImpersonatedEventPayload is dispatched when an administrator begins masquerading as a user.
	UserImpersonatedEventPayload struct {
		CallerID     string          `json:"caller_id"`
		CallerRole   string          `json:"caller_role"`
		TargetUserID string          `json:"target_user_id"`
		Session      *entity.Session `json:"session"`
		Extra        map[string]any  `json:"extra,omitempty"`
	}

	// ImpersonationStoppedEventPayload is dispatched when an impersonation session is ended.
	ImpersonationStoppedEventPayload struct {
		AdminUserID  string         `json:"admin_user_id"`
		TargetUserID string         `json:"target_user_id"`
		SessionToken string         `json:"session_token"`
		Extra        map[string]any `json:"extra,omitempty"`
	}

	// UserPasswordChangedEventPayload is dispatched when an administrator changes a user's password.
	UserPasswordChangedEventPayload struct {
		CallerID   string         `json:"caller_id"`
		CallerRole string         `json:"caller_role"`
		UserID     string         `json:"user_id"`
		Extra      map[string]any `json:"extra,omitempty"`
	}

	// SessionRevokedEventPayload is dispatched when a specific session is invalidated.
	SessionRevokedEventPayload struct {
		CallerID     string         `json:"caller_id"`
		CallerRole   string         `json:"caller_role"`
		SessionToken string         `json:"session_token"`
		Extra        map[string]any `json:"extra,omitempty"`
	}

	// AllSessionsRevokedEventPayload is dispatched when all sessions for a user are invalidated.
	AllSessionsRevokedEventPayload struct {
		CallerID   string         `json:"caller_id"`
		CallerRole string         `json:"caller_role"`
		UserID     string         `json:"user_id"`
		Extra      map[string]any `json:"extra,omitempty"`
	}
)
