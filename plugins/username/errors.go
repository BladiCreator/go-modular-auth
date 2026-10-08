package username

import "errors"

var (
	// ErrNotFound is returned when a username or user record is not found.
	ErrNotFound = errors.New("username: not found")

	// ErrTaken is returned when a username is already claimed by another user.
	ErrTaken = errors.New("username: already taken")

	// ErrAlreadyAssigned is returned when a user already has an assigned username.
	ErrAlreadyAssigned = errors.New("username: user already has a username")

	// ErrInvalidFormat is returned when a username violates syntactic or character rules.
	ErrInvalidFormat = errors.New("username: invalid format")

	// ErrTooShort is returned when a username is shorter than the configured minimum length.
	ErrTooShort = errors.New("username: too short")

	// ErrTooLong is returned when a username exceeds the configured maximum length.
	ErrTooLong = errors.New("username: too long")

	// ErrReserved is returned when a username matches a reserved name.
	ErrReserved = errors.New("username: reserved name")

	// ErrUserNotFound is returned when the corresponding Core user does not exist.
	ErrUserNotFound = errors.New("username: core user not found")

	// ErrInvalidCredentials is returned when authentication fails.
	// Preserves timing and error semantics of auth.ErrInvalidCredentials to prevent enumeration.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
)
