package passwordpolicy

import (
	"context"
)

// PasswordPolicy defines the capability exposed by the password policy plugin.
// Applications retrieve this capability via:
//
//	policyPlugin, err := auth.Get[plugins.PasswordPolicy](engine)
//	// or
//	policyPlugin, err := auth.Get[passwordpolicy.PasswordPolicy](engine)
type PasswordPolicy interface {
	// ValidatePassword evaluates a candidate password against the configured policy.
	// If userID is provided (non-empty), it also evaluates password reuse against history.
	ValidatePassword(ctx context.Context, password string, userID string) error

	// ValidatePasswordDetailed evaluates a candidate password and returns a structured
	// list of specific violation codes (e.g. "min_length", "complexity_uppercase", "compromised").
	ValidatePasswordDetailed(ctx context.Context, password string, userID string) (*ValidationResult, error)

	// ChangePassword enforces policy and history reuse prevention, executes Core ChangePassword,
	// and records the new password hash into history.
	ChangePassword(ctx context.Context, in ChangePasswordInput) error

	// ResetPassword enforces policy and history reuse prevention, executes Core ResetPassword,
	// and records the new password hash into history.
	ResetPassword(ctx context.Context, in ResetPasswordInput) error

	// RecordHistory adds a password hash into the user's password history and prunes old records.
	RecordHistory(ctx context.Context, userID, hash string) error

	// GetHistory retrieves historical password records for a user up to limit.
	GetHistory(ctx context.Context, userID string, limit int) ([]*PasswordHistory, error)

	// ClearHistory removes all historical password records for a user.
	ClearHistory(ctx context.Context, userID string) error

	// GetPolicy returns the currently active policy configuration.
	GetPolicy() Policy
}
