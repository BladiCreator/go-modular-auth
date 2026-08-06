// Package twofactor implements Two-Factor Authentication (2FA) via TOTP.
package twofactor

import "context"

// Repository defines the storage contract required by the TwoFactor plugin to persist and retrieve TOTP secrets.
type Repository interface {
	// SaveTOTPSecret stores a user's generated TOTP secret.
	SaveTOTPSecret(ctx context.Context, userID string, secret string) error
	// GetTOTPSecret retrieves a user's stored TOTP secret. Returns domain.ErrTOTPNotFound if not found.
	GetTOTPSecret(ctx context.Context, userID string) (string, error)
}