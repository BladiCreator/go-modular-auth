package lastloginmethod

import "errors"

var (
	// ErrRepositoryRequired is returned when StoreInDatabase is true but no Repository implementation is provided.
	ErrRepositoryRequired = errors.New("lastloginmethod: repository instance required when StoreInDatabase is enabled")

	// ErrMethodNotResolved is returned when the login method cannot be inferred from the request.
	ErrMethodNotResolved = errors.New("lastloginmethod: unable to resolve login method from request")

	// ErrUserNotFound is returned when attempting to update or retrieve last login method for a nonexistent user.
	ErrUserNotFound = errors.New("lastloginmethod: user not found")
)
