package ratelimit

import "errors"

var (
	// ErrRateLimitExceeded indicates that the client has performed too many requests within the window.
	ErrRateLimitExceeded = errors.New("ratelimit: rate limit exceeded")

	// ErrRateLimiterUnavailable indicates an infrastructure failure when FailClosed mode is active.
	ErrRateLimiterUnavailable = errors.New("ratelimit: rate limiter backend unavailable")

	// ErrInvalidPolicy indicates an unworkable or erroneous policy definition.
	ErrInvalidPolicy = errors.New("ratelimit: invalid policy configuration")

	// ErrActionRequired indicates that an evaluation request omitted the action name.
	ErrActionRequired = errors.New("ratelimit: action is required")
)
