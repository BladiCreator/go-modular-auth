package admin

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

type (
	// CallerContext carries identification, role, and metadata of the user initiating an administrative operation.
	CallerContext struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
		plugin.ExtraContainer
	}

	// CreateUserParams defines payload requirements for administrative user provisioning.
	CreateUserParams struct {
		Caller   CallerContext `json:"caller"`
		Name     string        `json:"name"`
		Email    string        `json:"email"`
		Password string        `json:"password,omitempty"`
		Role     string        `json:"role,omitempty"`
		plugin.ExtraContainer
	}

	// GetUserParams defines payload requirements for retrieving user details by ID.
	GetUserParams struct {
		Caller CallerContext `json:"caller"`
		UserID string        `json:"user_id"`
	}

	// ListUsersParams defines filtering and pagination parameters for user listings.
	ListUsersParams struct {
		Caller CallerContext   `json:"caller"`
		Filter ListUsersFilter `json:"filter"`
	}

	// ListUsersResult represents the paginated response containing user records and totals.
	ListUsersResult struct {
		Users  []*entity.User `json:"users"`
		Total  int64          `json:"total"`
		Limit  int            `json:"limit"`
		Offset int            `json:"offset"`
	}

	// UpdateUserParams defines partial update fields for an existing user account.
	UpdateUserParams struct {
		Caller        CallerContext `json:"caller"`
		UserID        string        `json:"user_id"`
		Name          *string       `json:"name,omitempty"`
		Email         *string       `json:"email,omitempty"`
		EmailVerified *bool         `json:"email_verified,omitempty"`
		Role          *string       `json:"role,omitempty"`
		Banned        *bool         `json:"banned,omitempty"`
		BanReason     *string       `json:"ban_reason,omitempty"`
		BanExpires    *time.Time    `json:"ban_expires,omitempty"`
		plugin.ExtraContainer
	}

	// RemoveUserParams defines parameters for permanently removing a user account.
	RemoveUserParams struct {
		Caller CallerContext `json:"caller"`
		UserID string        `json:"user_id"`
	}

	// SetRoleParams defines parameters for assigning a new role to a user.
	SetRoleParams struct {
		Caller CallerContext `json:"caller"`
		UserID string        `json:"user_id"`
		Role   string        `json:"role"`
	}

	// BanUserParams defines parameters for suspending a user account.
	BanUserParams struct {
		Caller       CallerContext  `json:"caller"`
		UserID       string         `json:"user_id"`
		BanReason    string         `json:"ban_reason,omitempty"`
		BanExpiresIn *time.Duration `json:"ban_expires_in,omitempty"`
	}

	// UnbanUserParams defines parameters for lifting a suspension from a user account.
	UnbanUserParams struct {
		Caller CallerContext `json:"caller"`
		UserID string        `json:"user_id"`
	}

	// SetUserPasswordParams defines parameters for setting a new password on a user account.
	SetUserPasswordParams struct {
		Caller      CallerContext `json:"caller"`
		UserID      string        `json:"user_id"`
		NewPassword string        `json:"new_password"`
	}

	// ImpersonateUserParams defines parameters for initiating user impersonation.
	ImpersonateUserParams struct {
		Caller    CallerContext  `json:"caller"`
		UserID    string         `json:"user_id"`
		IPAddress string         `json:"ip_address,omitempty"`
		UserAgent string         `json:"user_agent,omitempty"`
		Duration  *time.Duration `json:"duration,omitempty"`
	}

	// ImpersonateResult contains the newly issued masquerade session and target user profile.
	ImpersonateResult struct {
		Session           *entity.Session `json:"session"`
		User              *entity.User    `json:"user"`
		AdminSessionToken string          `json:"admin_session_token,omitempty"`
	}

	// StopImpersonatingParams defines tokens required to terminate an impersonation session.
	StopImpersonatingParams struct {
		ImpersonatedSessionToken string `json:"impersonated_session_token"`
		AdminSessionToken        string `json:"admin_session_token,omitempty"`
	}

	// StopImpersonatingResult contains the restored administrator session and profile.
	StopImpersonatingResult struct {
		AdminSession *entity.Session `json:"admin_session,omitempty"`
		AdminUser    *entity.User    `json:"admin_user"`
	}

	// ListUserSessionsParams defines parameters for listing active sessions of a user.
	ListUserSessionsParams struct {
		Caller CallerContext `json:"caller"`
		UserID string        `json:"user_id"`
	}

	// RevokeUserSessionParams defines parameters for invalidating a specific session token.
	RevokeUserSessionParams struct {
		Caller       CallerContext `json:"caller"`
		SessionToken string        `json:"session_token"`
	}

	// RevokeUserSessionsParams defines parameters for invalidating all active sessions of a user.
	RevokeUserSessionsParams struct {
		Caller CallerContext `json:"caller"`
		UserID string        `json:"user_id"`
	}

	// CheckPermissionParams defines parameters for evaluating permission statements against a caller.
	CheckPermissionParams struct {
		Caller      CallerContext `json:"caller"`
		Permissions Permissions   `json:"permissions"`
		Connector   Connector     `json:"connector,omitempty"`
	}
)
