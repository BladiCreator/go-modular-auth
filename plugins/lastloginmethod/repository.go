package lastloginmethod

import "context"

// Repository defines the persistence contract for updating and retrieving a user's last used login method.
type Repository interface {
	// UpdateLastLoginMethod persists the authentication method used by the specified user.
	UpdateLastLoginMethod(ctx context.Context, userID string, method string) error
	// GetLastLoginMethod retrieves the last used authentication method for the specified user.
	GetLastLoginMethod(ctx context.Context, userID string) (string, error)
}
