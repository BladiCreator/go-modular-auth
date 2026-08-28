package lastloginmethod

import (
	"context"
	"errors"
	"sync"
)

var (
	// ErrMethodNotResolved is returned when no login method can be inferred from the request path or context.
	ErrMethodNotResolved = errors.New("lastloginmethod: authentication method could not be resolved")

	// ErrUserNotFound is returned when no user record matches the queried user ID.
	ErrUserNotFound = errors.New("lastloginmethod: user not found")

	// ErrRepositoryRequired is returned when database persistence is enabled but no Repository is configured.
	ErrRepositoryRequired = errors.New("lastloginmethod: repository is required when storeInDatabase is enabled")
)

// Repository defines the persistent storage contract required by the LastLoginMethod plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormLastLoginMethodRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormLastLoginMethodRepository) UpdateLastLoginMethod(ctx context.Context, userID string, method string) error {
//		res := r.db.WithContext(ctx).Model(&entity.User{}).Where("id = ?", userID).Update("last_login_method", method)
//		if res.Error != nil {
//			return res.Error
//		}
//		if res.RowsAffected == 0 {
//			return lastloginmethod.ErrUserNotFound
//		}
//		return nil
//	}
//
//	func (r *GormLastLoginMethodRepository) GetLastLoginMethod(ctx context.Context, userID string) (string, error) {
//		var method string
//		if err := r.db.WithContext(ctx).Model(&entity.User{}).Where("id = ?", userID).Pluck("last_login_method", &method).Error; err != nil {
//			if errors.Is(err, gorm.ErrRecordNotFound) {
//				return "", lastloginmethod.ErrUserNotFound
//			}
//			return "", err
//		}
//		return method, nil
//	}
type Repository interface {
	// UpdateLastLoginMethod persists the authentication method used by the specified user.
	//
	// Function:
	//   Called after successful user authentication to store the last used login method (e.g. "email_password", "passkey", "google").
	//
	// Storage:
	//   Database (GORM / SQL) - Updates last_login_method column on users table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user primary key ID.
	//   - method: Identifier string of the login method used.
	//
	// Returns:
	//   - error: Nil on success, ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   UPDATE users SET last_login_method = $1, updated_at = NOW() WHERE id = $2;
	UpdateLastLoginMethod(ctx context.Context, userID string, method string) error

	// GetLastLoginMethod retrieves the last used authentication method for the specified user.
	//
	// Function:
	//   Used to pre-select or highlight the user's preferred login method on sign-in screens.
	//
	// Storage:
	//   Database (GORM / SQL) - Query last_login_method column by user ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - userID: Target user primary key ID.
	//
	// Returns:
	//   - string: Method identifier string if set (e.g. "email_password", "passkey", "google").
	//   - error: Nil on success, ErrUserNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT last_login_method FROM users WHERE id = $1 LIMIT 1;
	GetLastLoginMethod(ctx context.Context, userID string) (string, error)
}

// MemoryRepository provides a thread-safe, in-memory implementation of Repository for testing and lightweight usage.
type MemoryRepository struct {
	mu      sync.RWMutex
	methods map[string]string // userID -> last_login_method
}

// NewMemoryRepository initializes a fresh MemoryRepository instance.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		methods: make(map[string]string),
	}
}

// UpdateLastLoginMethod stores a user's last login method in memory.
func (r *MemoryRepository) UpdateLastLoginMethod(_ context.Context, userID string, method string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.methods[userID] = method
	return nil
}

// GetLastLoginMethod retrieves a user's last login method from memory.
func (r *MemoryRepository) GetLastLoginMethod(_ context.Context, userID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	method, ok := r.methods[userID]
	if !ok || method == "" {
		return "", ErrUserNotFound
	}
	return method, nil
}
