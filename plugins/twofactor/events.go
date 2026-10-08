package twofactor

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Event names emitted by the twofactor plugin.
const (
	// EventTwoFactorEnabled is emitted when a user successfully confirms enrollment of their first MFA factor.
	EventTwoFactorEnabled auth.EventName = "twofactor.enabled"

	// EventTwoFactorDisabled is emitted when MFA is disabled for a user.
	EventTwoFactorDisabled auth.EventName = "twofactor.disabled"

	// EventTwoFactorVerified is emitted when a user successfully verifies a secondary factor (TOTP or recovery code).
	EventTwoFactorVerified auth.EventName = "twofactor.verified"
)

// TwoFactorEnabledPayload represents observational data when 2FA is enabled.
type TwoFactorEnabledPayload struct {
	UserID     string     `json:"user_id"`
	FactorID   string     `json:"factor_id"`
	FactorType FactorType `json:"factor_type"`
	EnabledAt  time.Time  `json:"enabled_at"`
}

// TwoFactorDisabledPayload represents observational data when 2FA is disabled.
type TwoFactorDisabledPayload struct {
	UserID     string    `json:"user_id"`
	DisabledAt time.Time `json:"disabled_at"`
	Reason     string    `json:"reason,omitempty"`
}

// TwoFactorVerifiedPayload represents observational data when a factor is verified.
type TwoFactorVerifiedPayload struct {
	UserID         string         `json:"user_id"`
	FactorID       string         `json:"factor_id,omitempty"`
	FactorType     FactorType     `json:"factor_type"`
	AssuranceLevel AssuranceLevel `json:"assurance_level"`
	VerifiedAt     time.Time      `json:"verified_at"`
}
