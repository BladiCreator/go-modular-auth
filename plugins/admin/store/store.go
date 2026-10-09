// Package store defines the persistence contract for administrative state in GoModularAuth.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that the requested administrative record does not exist.
	ErrNotFound = errors.New("admin store: record not found")

	// ErrConflict indicates that a duplicate key or constraint violation occurred.
	ErrConflict = errors.New("admin store: record conflict")
)

// UserRecord represents administrative metadata and lifecycle state associated with a Core User.
type UserRecord struct {
	UserID         string            `json:"user_id"`
	Email          string            `json:"email"`
	Disabled       bool              `json:"disabled"`
	DisabledAt     *time.Time        `json:"disabled_at,omitempty"`
	DisabledReason string            `json:"disabled_reason,omitempty"`
	IsAdmin        bool              `json:"is_admin"`
	Role           string            `json:"role,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// Active reports whether the user is not disabled.
func (r *UserRecord) Active() bool {
	return r != nil && !r.Disabled
}

// ListFilter specifies parameters for querying administrative user lists.
type ListFilter struct {
	Limit  int
	Offset int
	Search string // Prefix or substring match for email
	Status string // "all", "active", "disabled"
}

// Store defines the persistent storage contract required by the admin plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormAdminStore struct {
//		db *gorm.DB
//	}
//
//	func (s *GormAdminStore) GetUser(ctx context.Context, userID string) (*store.UserRecord, error) {
//		var rec store.UserRecord
//		if err := s.db.WithContext(ctx).Where("user_id = ?", userID).First(&rec).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return nil, store.ErrNotFound
//			}
//			return nil, err
//		}
//		return &rec, nil
//	}
//
// # Storage and Caching Recommendation (Redis / Cache-Aside Strategy):
//
// Because `IsUserDisabled` is checked during authentication workflows to reject disabled accounts,
// querying the database on every sign-in can become a performance bottleneck.
// Decorating your database store with Redis or an in-memory Cache-Aside wrapper is strongly recommended:
//
//	type CachedAdminStore struct {
//		dbStore store.Store
//		redis   *redis.Client
//		ttl     time.Duration
//	}
//
//	func (s *CachedAdminStore) IsUserDisabled(ctx context.Context, userID string) (bool, error) {
//		cacheKey := "gomodularauth:admin:disabled:" + userID
//		val, err := s.redis.Get(ctx, cacheKey).Result()
//		if err == nil {
//			return val == "1", nil // Fast Cache Hit ($O(1)$)
//		}
//		disabled, err := s.dbStore.IsUserDisabled(ctx, userID)
//		if err != nil {
//			return false, err
//		}
//		valStr := "0"
//		if disabled {
//			valStr = "1"
//		}
//		s.redis.Set(ctx, cacheKey, valStr, s.ttl)
//		return disabled, nil
//	}
type Store interface {
	// Transaction runs fn atomically within a storage transaction.
	//
	// Function:
	//   Ensures atomic multi-entity administrative operations.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - fn: Transaction function callback.
	//
	// Returns:
	//   - error: Nil on commit, or error causing rollback.
	//
	// Example SQL:
	//   BEGIN; ... COMMIT;
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error

	// UpsertUser persists or updates administrative record for a user.
	//
	// Function:
	//   Invoked upon user creation hook or administrative update to ensure indexing.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - r: Administrative user record.
	//
	// Returns:
	//   - error: Nil on success, or infrastructure error.
	//
	// Example SQL:
	//   INSERT INTO auth_admin_users (user_id, email, disabled, disabled_at, disabled_reason, is_admin, role, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email, disabled = EXCLUDED.disabled, disabled_at = EXCLUDED.disabled_at, disabled_reason = EXCLUDED.disabled_reason, is_admin = EXCLUDED.is_admin, role = EXCLUDED.role, metadata = EXCLUDED.metadata, updated_at = EXCLUDED.updated_at;
	UpsertUser(ctx context.Context, r *UserRecord) error

	// GetUser retrieves the administrative user record by UserID.
	//
	// Function:
	//   Queries administrative metadata, disabled status, and role.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - High-frequency lookup.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target Core User ID.
	//
	// Returns:
	//   - *store.UserRecord: Record if found.
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   SELECT user_id, email, disabled, disabled_at, disabled_reason, is_admin, role, metadata, created_at, updated_at FROM auth_admin_users WHERE user_id = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "gomodularauth:admin:user:" + userID).Bytes()
	GetUser(ctx context.Context, userID string) (*UserRecord, error)

	// UpdateUserStatus modifies the disabled status and reason for a user.
	//
	// Function:
	//   Invoked when disabling or enabling a user.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//   - disabled: Whether the user account is disabled.
	//   - reason: Reason for suspension or empty if active.
	//   - at: Timestamp of status modification.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_admin_users SET disabled = $1, disabled_reason = $2, disabled_at = $3, updated_at = $4 WHERE user_id = $5;
	UpdateUserStatus(ctx context.Context, userID string, disabled bool, reason string, at *time.Time) error

	// DeleteUser removes administrative record when a user is deleted.
	//
	// Function:
	//   Invoked during full user deletion workflow.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//
	// Returns:
	//   - error: ErrNotFound if not found, or infrastructure error.
	//
	// Example SQL:
	//   DELETE FROM auth_admin_users WHERE user_id = $1;
	DeleteUser(ctx context.Context, userID string) error

	// ListUsers returns paginated administrative user records matching filter criteria.
	//
	// Function:
	//   Serves administrative dashboard user listings and search.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - filter: Pagination, status, and search filters.
	//
	// Returns:
	//   - []*store.UserRecord: Slice of records.
	//   - int: Total matching count.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   SELECT user_id, email, disabled, disabled_at, disabled_reason, is_admin, role, metadata, created_at, updated_at FROM auth_admin_users WHERE ($1 = '' OR email ILIKE '%' || $1 || '%') ORDER BY created_at DESC LIMIT $2 OFFSET $3;
	ListUsers(ctx context.Context, filter ListFilter) ([]*UserRecord, int, error)

	// IsUserDisabled checks whether a user account is flagged as disabled.
	//
	// Function:
	//   Invoked prior to authenticating credentials in BeforeSignIn hook.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - High-frequency authentication check.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//
	// Returns:
	//   - bool: True if user exists and is disabled.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   SELECT disabled FROM auth_admin_users WHERE user_id = $1 LIMIT 1;
	//
	// Example Cache (Redis):
	//   val, err := rdb.Get(ctx, "gomodularauth:admin:disabled:" + userID).Bytes()
	IsUserDisabled(ctx context.Context, userID string) (bool, error)

	// IsAdmin checks whether a user possesses global administrative privileges.
	//
	// Function:
	//   Invoked during default administrative authorization checks.
	//
	// Storage:
	//   Both (Cache-Aside Strategy) - Administrative request authorization.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Authenticated principal subject.
	//
	// Returns:
	//   - bool: True if user is an administrator.
	//   - error: Infrastructure error.
	//
	// Example SQL:
	//   SELECT is_admin FROM auth_admin_users WHERE user_id = $1 LIMIT 1;
	IsAdmin(ctx context.Context, userID string) (bool, error)

	// SetAdminRole updates administrative privilege and role title for a user.
	//
	// Function:
	//   Grants or revokes administrator status.
	//
	// Storage:
	//   Database (GORM / SQL).
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user ID.
	//   - isAdmin: Flag indicating administrative access.
	//   - role: Named administrative role (e.g. "superadmin", "support").
	//
	// Returns:
	//   - error: ErrNotFound if user not found, or infrastructure error.
	//
	// Example SQL:
	//   UPDATE auth_admin_users SET is_admin = $1, role = $2, updated_at = $3 WHERE user_id = $4;
	SetAdminRole(ctx context.Context, userID string, isAdmin bool, role string) error
}
