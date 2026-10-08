package multisession

import "errors"

var (
	// ErrSessionNotFound is returned when the target session does not exist.
	ErrSessionNotFound = errors.New("multisession: session not found")

	// ErrSessionAlreadyRevoked is returned when operating on an already revoked session.
	ErrSessionAlreadyRevoked = errors.New("multisession: session already revoked")

	// ErrInvalidInput is returned when required parameters (e.g., userID, sessionID) are empty or malformed.
	ErrInvalidInput = errors.New("multisession: invalid input")

	// ErrUnauthorized is returned when a session does not belong to the specified user.
	ErrUnauthorized = errors.New("multisession: unauthorized session access")

	// ErrMaxConcurrentSessionsReached is returned when a new session cannot be created
	// because the user reached the configured maximum allowed concurrent sessions and
	// the overflow policy is set to OverflowReject.
	ErrMaxConcurrentSessionsReached = errors.New("multisession: maximum concurrent sessions reached")

	// ErrMetadataNotFound is returned when no metadata is stored for the requested session.
	ErrMetadataNotFound = errors.New("multisession: session metadata not found")
)
