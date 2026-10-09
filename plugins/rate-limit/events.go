package ratelimit

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Rate limiting event names emitted to the GoModularAuth event bus.
const (
	EventRateLimitExceeded auth.EventName = "ratelimit.exceeded"
	EventRateLimitReset    auth.EventName = "ratelimit.reset"
)

// ExceededPayload describes a throttled request event for security auditing.
type ExceededPayload struct {
	Action     string        `json:"action"`
	Key        string        `json:"key"`
	RetryAfter time.Duration `json:"retry_after"`
	OccurredAt time.Time     `json:"occurred_at"`
}
