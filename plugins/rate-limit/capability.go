package ratelimit

import "context"

// RateLimit represents the strongly typed capability provided by the rate-limit plugin.
// Applications retrieve this capability via auth.Get[plugins.RateLimit]().
type RateLimit interface {
	// Check evaluates whether a request exceeds configured rate limits without consuming capacity.
	Check(ctx context.Context, req Request) (*Decision, error)

	// Allow evaluates and consumes one token if within limits, returning the full evaluation decision.
	Allow(ctx context.Context, req Request) (*Decision, error)

	// Require checks and consumes a token, returning ErrRateLimitExceeded if throttled.
	Require(ctx context.Context, req Request) error

	// Reset clears active rate limit counters for a given request target (e.g. upon successful authentication).
	Reset(ctx context.Context, req Request) error

	// Policy retrieves the currently configured policy for an action.
	Policy(action string) (Policy, bool)

	// SetPolicy registers or dynamically overrides the policy for an action.
	SetPolicy(policy Policy) error
}
