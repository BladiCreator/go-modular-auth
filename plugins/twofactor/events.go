// Package twofactor defines event names and typed event payloads published by the TwoFactor plugin on the global EventBus.
package twofactor

import (
	"time"
)

const (
	// EventEnableTwoFactorBefore is emitted right before starting 2FA enrollment for a user.
	// Payload: *EnableTwoFactorBeforeEventPayload
	EventEnableTwoFactorBefore = "twofactor:enable:before"

	// EventEnableTwoFactorAfter is emitted after successfully generating and persisting 2FA secrets and backup codes.
	// Payload: *EnableTwoFactorAfterEventPayload
	EventEnableTwoFactorAfter = "twofactor:enable:after"

	// EventDisableTwoFactorBefore is emitted before disabling 2FA credentials for a user.
	// Payload: *DisableTwoFactorEventPayload
	EventDisableTwoFactorBefore = "twofactor:disable:before"

	// EventDisableTwoFactorAfter is emitted after 2FA credentials have been removed from storage.
	// Payload: *DisableTwoFactorEventPayload
	EventDisableTwoFactorAfter = "twofactor:disable:after"

	// EventVerifyTOTPBefore is emitted before validating a user-provided TOTP code.
	// Payload: *VerifyTOTPBeforeEventPayload
	EventVerifyTOTPBefore = "twofactor:verify_totp:before"

	// EventVerifyTOTPAfter is emitted after verifying a TOTP code, indicating success or failure.
	// Payload: *VerifyTOTPAfterEventPayload
	EventVerifyTOTPAfter = "twofactor:verify_totp:after"

	// EventSendOTPBefore is emitted before generating and sending an SMS/Email OTP challenge.
	// Payload: *SendOTPBeforeEventPayload
	EventSendOTPBefore = "twofactor:send_otp:before"

	// EventSendOTPAfter is emitted after an OTP challenge has been successfully dispatched.
	// Payload: *SendOTPAfterEventPayload
	EventSendOTPAfter = "twofactor:send_otp:after"

	// EventVerifyOTPAfter is emitted after validating an active OTP challenge.
	// Payload: *VerifyOTPAfterEventPayload
	EventVerifyOTPAfter = "twofactor:verify_otp:after"

	// EventVerifyBackupCodeAfter is emitted after verifying and consuming a single-use backup code.
	// Payload: *VerifyBackupCodeAfterEventPayload
	EventVerifyBackupCodeAfter = "twofactor:verify_backup_code:after"

	// EventTOTPGenerated is emitted whenever a raw Base32 TOTP secret is created.
	// Payload: *TOTPGeneratedEventPayload
	EventTOTPGenerated = "twofactor:totp:generated"
)

// Typed Event Payloads

// EnableTwoFactorBeforeEventPayload contains the user ID and mutable parameters for pre-enrollment interception.
type EnableTwoFactorBeforeEventPayload struct {
	// UserID identifies the user beginning 2FA setup.
	UserID string

	// Params holds the mutable enrollment parameters (including dynamic Extra metadata).
	Params *EnableParams
}

// EnableTwoFactorAfterEventPayload contains confirmation details after 2FA secrets have been created.
type EnableTwoFactorAfterEventPayload struct {
	// UserID identifies the user whose 2FA enrollment completed.
	UserID string

	// BackupCodesCount is the number of single-use backup codes generated.
	BackupCodesCount int
}

// DisableTwoFactorEventPayload contains the user ID associated with a 2FA disablement event.
type DisableTwoFactorEventPayload struct {
	// UserID identifies the user whose 2FA configuration is being disabled.
	UserID string
}

// VerifyTOTPBeforeEventPayload contains details before a TOTP code is evaluated.
type VerifyTOTPBeforeEventPayload struct {
	// UserID identifies the user submitting the TOTP code.
	UserID string
}

// VerifyTOTPAfterEventPayload reports the result of a TOTP code validation attempt.
type VerifyTOTPAfterEventPayload struct {
	// UserID identifies the user who attempted TOTP validation.
	UserID string

	// Success indicates whether the submitted code was valid and accepted.
	Success bool
}

// SendOTPBeforeEventPayload contains details before an OTP challenge is created.
type SendOTPBeforeEventPayload struct {
	// UserID identifies the target user for the OTP challenge.
	UserID string
}

// SendOTPAfterEventPayload contains confirmation details after an OTP challenge has been dispatched.
type SendOTPAfterEventPayload struct {
	// UserID identifies the target user for the OTP challenge.
	UserID string

	// ExpiresAt specifies the exact expiration time for the OTP challenge.
	ExpiresAt time.Time
}

// VerifyOTPAfterEventPayload reports the result of an OTP challenge verification attempt.
type VerifyOTPAfterEventPayload struct {
	// UserID identifies the user attempting OTP challenge verification.
	UserID string

	// Success indicates whether the challenge code was valid.
	Success bool
}

// VerifyBackupCodeAfterEventPayload reports the result of a single-use backup code consumption attempt.
type VerifyBackupCodeAfterEventPayload struct {
	// UserID identifies the user consuming a backup code.
	UserID string

	// Success indicates whether the backup code was found, valid, and consumed.
	Success bool

	// RemainingCodes is the count of remaining unconsumed backup codes.
	RemainingCodes int
}

// TOTPGeneratedEventPayload contains the raw secret generated during 2FA setup.
type TOTPGeneratedEventPayload struct {
	// UserID identifies the user for whom the secret was created.
	UserID string

	// Secret is the Base32-encoded TOTP secret.
	Secret string
}
