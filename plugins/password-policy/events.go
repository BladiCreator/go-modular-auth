package passwordpolicy

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventPolicyValidated is emitted when a candidate password successfully passes all policy checks.
	EventPolicyValidated auth.EventName = "password_policy.validated"

	// EventPolicyViolation is emitted when a password fails policy enforcement.
	EventPolicyViolation auth.EventName = "password_policy.violation"

	// EventHistoryRecorded is emitted when a new password hash is stored in user history.
	EventHistoryRecorded auth.EventName = "password_policy.history_recorded"
)

// PolicyValidatedPayload carries audit details for successful validations.
type PolicyValidatedPayload struct {
	UserID    string    `json:"user_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// PolicyViolationPayload carries audit details for policy violations.
type PolicyViolationPayload struct {
	UserID     string    `json:"user_id,omitempty"`
	Violations []string  `json:"violations"`
	Timestamp  time.Time `json:"timestamp"`
}

// HistoryRecordedPayload carries audit details when a password hash is preserved in history.
type HistoryRecordedPayload struct {
	UserID    string    `json:"user_id"`
	HistoryID string    `json:"history_id"`
	Timestamp time.Time `json:"timestamp"`
}
