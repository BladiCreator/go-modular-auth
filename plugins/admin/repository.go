package admin

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

var (
	// ErrUserNotFound is returned when no user matches the queried identifier or email.
	ErrUserNotFound = errors.New("admin: user not found")

	// ErrUserAlreadyExists is returned when attempting to create a user with an email already taken.
	ErrUserAlreadyExists = errors.New("admin: user already exists")

	// ErrCannotBanSelf is returned when an administrator attempts to ban their own account.
	ErrCannotBanSelf = errors.New("admin: you cannot ban yourself")

	// ErrCannotDeleteSelf is returned when an administrator attempts to remove their own account.
	ErrCannotDeleteSelf = errors.New("admin: you cannot remove yourself")

	// ErrCannotImpersonateAdmin is returned when attempting to impersonate an administrator without explicit permission.
	ErrCannotImpersonateAdmin = errors.New("admin: you cannot impersonate admins without explicit permission")

	// ErrCannotImpersonateSelf is returned when attempting to impersonate oneself.
	ErrCannotImpersonateSelf = errors.New("admin: you cannot impersonate yourself")

	// ErrNotImpersonating is returned when attempting to stop impersonation on a session that is not impersonated.
	ErrNotImpersonating = errors.New("admin: session is not impersonated")

	// ErrAdminSessionNotFound is returned when the original administrator session cannot be found during restoration.
	ErrAdminSessionNotFound = errors.New("admin: original admin session not found")

	// ErrUnauthorized is returned when unauthenticated access is attempted.
	ErrUnauthorized = errors.New("admin: unauthorized access")

	// ErrForbidden is returned when a caller lacks the required administrative permissions.
	ErrForbidden = errors.New("admin: forbidden - insufficient permissions")

	// ErrInvalidRole is returned when assigning a role that is not recognized in the access control configuration.
	ErrInvalidRole = errors.New("admin: invalid or non-existent role")

	// ErrNoDataToUpdate is returned when an update request provides no fields to modify.
	ErrNoDataToUpdate = errors.New("admin: no data provided for update")

	// ErrPasswordTooShort is returned when a new password does not meet the minimum length constraint.
	ErrPasswordTooShort = errors.New("admin: password is too short")

	// ErrPasswordTooLong is returned when a new password exceeds the maximum allowed length.
	ErrPasswordTooLong = errors.New("admin: password is too long")

	// ErrInvalidEmail is returned when an email format validation fails.
	ErrInvalidEmail = errors.New("admin: invalid email address")

	// ErrUserBanned is returned when attempting an operation or authentication on a banned account.
	ErrUserBanned = errors.New("admin: user account is banned")

	// ErrInvalidParameter is returned when a required parameter is missing or malformed.
	ErrInvalidParameter = errors.New("admin: required parameter is missing or invalid")
)

// ListUsersFilter defines search, filter, sorting, and pagination criteria for user listings.
type ListUsersFilter struct {
	SearchValue    string `json:"search_value,omitempty"`    // Search query term
	SearchField    string `json:"search_field,omitempty"`    // Target field to search ("email", "name", etc.)
	SearchOperator string `json:"search_operator,omitempty"` // "contains", "starts_with", "ends_with", "exact"
	FilterField    string `json:"filter_field,omitempty"`    // Attribute field to filter by (e.g. "role", "banned")
	FilterOperator string `json:"filter_operator,omitempty"` // "eq", "ne", "in", etc.
	FilterValue    any    `json:"filter_value,omitempty"`    // Target value for the filter condition
	SortBy         string `json:"sort_by,omitempty"`         // Field to sort by ("created_at", "email", "name")
	SortDirection  string `json:"sort_direction,omitempty"`  // "asc" or "desc"
	Limit          int    `json:"limit,omitempty"`           // Number of records per page
	Offset         int    `json:"offset,omitempty"`          // Pagination offset
}

// Repository defines the persistent storage contract required by the Admin plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
type Repository interface {
	// GetUserByID retrieves a user entity matching the provided unique identifier.
	// Example SQL: SELECT id, name, email, email_verified, two_factor_enabled, role, banned, ban_reason, ban_expires, created_at, updated_at FROM users WHERE id = $1 LIMIT 1;
	GetUserByID(ctx context.Context, id string) (*entity.User, error)

	// GetUserByEmail retrieves a user entity matching the provided normalized email address.
	// Example SQL: SELECT id, name, email, email_verified, two_factor_enabled, role, banned, ban_reason, ban_expires, created_at, updated_at FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1;
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)

	// CreateUser persists a newly created user entity in storage.
	// Example SQL: INSERT INTO users (id, name, email, role, banned, ban_reason, ban_expires, email_verified, two_factor_enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
	CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error)

	// UpdateUser updates modified fields of an existing user profile in storage.
	// Example SQL: UPDATE users SET name = $1, email = $2, role = $3, banned = $4, ban_reason = $5, ban_expires = $6, email_verified = $7, updated_at = $8 WHERE id = $9;
	UpdateUser(ctx context.Context, user *entity.User) error

	// DeleteUser removes a user record and their related accounts and credentials from storage.
	// Example SQL: DELETE FROM users WHERE id = $1;
	DeleteUser(ctx context.Context, id string) error

	// ListUsers returns a paginated and filtered list of user records matching the filter criteria.
	// Example SQL: SELECT id, name, email, role, banned, ban_reason, ban_expires, email_verified, created_at, updated_at FROM users WHERE email ILIKE '%' || $1 || '%' ORDER BY created_at DESC LIMIT $2 OFFSET $3;
	ListUsers(ctx context.Context, filter ListUsersFilter) ([]*entity.User, int64, error)

	// LinkCredentialAccount links or updates provider credential password hashes for a user.
	// Example SQL: INSERT INTO accounts (id, user_id, provider_id, password_hash, created_at, updated_at) VALUES ($1, $2, 'credential', $3, $4, $5) ON CONFLICT (user_id, provider_id) DO UPDATE SET password_hash = $3, updated_at = $5;
	LinkCredentialAccount(ctx context.Context, userID, passwordHash string) error

	// CreateSession persists a new session entity (supporting impersonation tracking).
	// Example SQL: INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent, impersonated_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
	CreateSession(ctx context.Context, session *dto.CreateSessionParams) (*entity.Session, error)

	// GetSessionByToken retrieves an active session by its raw token string.
	// Example SQL: SELECT id, user_id, token, expires_at, ip_address, user_agent, impersonated_by, created_at, updated_at FROM sessions WHERE token = $1 LIMIT 1;
	GetSessionByToken(ctx context.Context, token string) (*entity.Session, error)

	// ListSessionsByUserID lists all active sessions belonging to the specified user.
	// Example SQL: SELECT id, user_id, token, expires_at, ip_address, user_agent, impersonated_by, created_at, updated_at FROM sessions WHERE user_id = $1;
	ListSessionsByUserID(ctx context.Context, userID string) ([]*entity.Session, error)

	// DeleteSession deletes a specific session by token.
	// Example SQL: DELETE FROM sessions WHERE token = $1;
	DeleteSession(ctx context.Context, token string) error

	// DeleteSessionsByUserID deletes all active sessions belonging to a user (used during bans and global revocation).
	// Example SQL: DELETE FROM sessions WHERE user_id = $1;
	DeleteSessionsByUserID(ctx context.Context, userID string) error
}
