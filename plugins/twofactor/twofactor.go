package twofactor

import (
	"context"
	"time"
)

// FactorType represents an authentication second factor kind.
type FactorType string

const (
	// FactorTypeTOTP represents Time-based One-Time Password (RFC 6238).
	FactorTypeTOTP FactorType = "totp"

	// FactorTypeRecoveryCodes represents single-use backup recovery codes.
	FactorTypeRecoveryCodes FactorType = "recovery_codes"
)

// AssuranceLevel classifies the level of confidence in the authenticated identity (NIST SP 800-63B).
type AssuranceLevel string

const (
	// AAL1 represents single-factor authentication (e.g. password, magic link, email OTP alone).
	AAL1 AssuranceLevel = "aal1"

	// AAL2 represents multi-factor authentication (primary factor plus a confirmed secondary factor).
	AAL2 AssuranceLevel = "aal2"
)

type assuranceLevelKey struct{}

// WithAssuranceLevel returns a new context bearing the specified AssuranceLevel.
func WithAssuranceLevel(ctx context.Context, level AssuranceLevel) context.Context {
	return context.WithValue(ctx, assuranceLevelKey{}, level)
}

// AssuranceLevelFrom retrieves the AssuranceLevel from the context, defaulting to AAL1 if absent.
func AssuranceLevelFrom(ctx context.Context) (AssuranceLevel, bool) {
	val, ok := ctx.Value(assuranceLevelKey{}).(AssuranceLevel)
	if !ok || val == "" {
		return AAL1, false
	}
	return val, true
}

// RequireAAL2 checks whether the context has achieved AssuranceLevel 2. Returns ErrAssuranceLevelInsufficient if not.
func RequireAAL2(ctx context.Context) error {
	level, ok := AssuranceLevelFrom(ctx)
	if !ok || level != AAL2 {
		return ErrAssuranceLevelInsufficient
	}
	return nil
}

// Factor represents a registered second factor.
// It deliberately omits any plaintext or encrypted secrets so normal APIs cannot leak sensitive material.
type Factor struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Type        FactorType `json:"type"`
	Label       string     `json:"label,omitempty"`
	Confirmed   bool       `json:"confirmed"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Status summarizes the two-factor authentication configuration for a user.
type Status struct {
	Enabled            bool       `json:"enabled"`
	Factors            []Factor   `json:"factors"`
	RecoveryCodesCount int        `json:"recovery_codes_count"`
	PrimaryFactorType  FactorType `json:"primary_factor_type,omitempty"`
}

// TOTPEnrollment contains the setup data returned ONCE during TOTP enrollment initiation.
// Applications present this secret or URI to the user (e.g., via QR code).
type TOTPEnrollment struct {
	FactorID        string `json:"factor_id"`
	Secret          string `json:"secret"`           // Plaintext base32 secret; returned only during enrollment
	ProvisioningURI string `json:"provisioning_uri"` // Standard otpauth:// URI for QR code generation
	Issuer          string `json:"issuer"`
	AccountName     string `json:"account_name"`
}

// VerifyResult details the successful verification of an MFA factor.
type VerifyResult struct {
	UserID         string         `json:"user_id"`
	FactorID       string         `json:"factor_id,omitempty"`
	FactorType     FactorType     `json:"factor_type"`
	AssuranceLevel AssuranceLevel `json:"assurance_level"`
	VerifiedAt     time.Time      `json:"verified_at"`
}

// Challenge represents an ephemeral MFA challenge issued when a user completes primary authentication
// and must satisfy a second factor challenge to gain full session privileges.
type Challenge struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// EnrollConfig holds optional parameters for TOTP enrollment.
type EnrollConfig struct {
	Label       string
	Issuer      string
	AccountName string
}

// EnrollOption configures an enrollment request.
type EnrollOption func(*EnrollConfig)

// WithEnrollLabel sets a human-friendly label for the factor (e.g. "Work iPhone").
func WithEnrollLabel(label string) EnrollOption {
	return func(c *EnrollConfig) {
		c.Label = label
	}
}

// WithEnrollIssuer sets a custom issuer name for the otpauth URI.
func WithEnrollIssuer(issuer string) EnrollOption {
	return func(c *EnrollConfig) {
		c.Issuer = issuer
	}
}

// WithEnrollAccountName sets the account name in the otpauth URI (e.g. user's email).
func WithEnrollAccountName(accountName string) EnrollOption {
	return func(c *EnrollConfig) {
		c.AccountName = accountName
	}
}

// TwoFactor is the strongly typed capability provided by the twofactor plugin.
type TwoFactor interface {
	// GetStatus returns the complete 2FA status and configured factors for a user.
	GetStatus(ctx context.Context, userID string) (*Status, error)

	// IsEnabled reports whether the user has at least one confirmed MFA factor.
	IsEnabled(ctx context.Context, userID string) (bool, error)

	// ListFactors returns all registered factors (confirmed or pending) for a user.
	ListFactors(ctx context.Context, userID string) ([]Factor, error)

	// EnrollTOTP initiates TOTP enrollment. It creates a pending factor and returns the secret & provisioning URI.
	// The factor remains inactive until confirmed via ConfirmTOTP.
	EnrollTOTP(ctx context.Context, userID string, opts ...EnrollOption) (*TOTPEnrollment, error)

	// ConfirmTOTP confirms a pending TOTP factor with a valid code from the authenticator app.
	// Upon success, the factor is activated and EventTwoFactorEnabled is emitted.
	ConfirmTOTP(ctx context.Context, userID, factorID, code string) error

	// VerifyTOTP verifies a TOTP code for a user against their confirmed TOTP factors.
	// It applies clock-skew tolerance and prevents replay attacks. Emits EventTwoFactorVerified.
	VerifyTOTP(ctx context.Context, userID, code string) (*VerifyResult, error)

	// VerifyRecoveryCode verifies and consumes a single-use backup recovery code.
	// Emits EventTwoFactorVerified upon successful consumption.
	VerifyRecoveryCode(ctx context.Context, userID, code string) (*VerifyResult, error)

	// CreateChallenge creates a short-lived MFA challenge for two-step authentication flows.
	CreateChallenge(ctx context.Context, userID string) (*Challenge, error)

	// VerifyChallenge verifies a challenge token with either a TOTP code or a recovery code.
	VerifyChallenge(ctx context.Context, challengeID, code string) (*VerifyResult, error)

	// GenerateRecoveryCodes generates a fresh set of recovery codes, hashing them before storing.
	// Returns the plaintext codes ONCE.
	GenerateRecoveryCodes(ctx context.Context, userID string, count int) ([]string, error)

	// RotateRecoveryCodes revokes all existing recovery codes for a user and generates a fresh set.
	RotateRecoveryCodes(ctx context.Context, userID string) ([]string, error)

	// GetRemainingRecoveryCodesCount returns the number of unused active recovery codes.
	GetRemainingRecoveryCodesCount(ctx context.Context, userID string) (int, error)

	// Disable disables MFA for a user by removing all factors and recovery codes.
	// Emits EventTwoFactorDisabled.
	Disable(ctx context.Context, userID string) error

	// DisableFactor removes a specific factor. If no confirmed factors remain, MFA is effectively disabled.
	DisableFactor(ctx context.Context, userID, factorID string) error
}
