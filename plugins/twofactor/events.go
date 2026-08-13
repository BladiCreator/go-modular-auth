// Package twofactor defines event names and typed event payloads published by the TwoFactor plugin on the global EventBus.
package twofactor

import (
	"time"
)

const (
	// EventEnableBefore is emitted right before starting 2FA enrollment for a user.
	// Payload: *EnableBeforeEventPayload
	EventEnableBefore = "twofactor:enable:before"

	// EventEnableAfter is emitted after successfully generating and persisting 2FA secrets and backup codes.
	// Payload: *EnableAfterEventPayload
	EventEnableAfter = "twofactor:enable:after"

	// EventDisableBefore is emitted before disabling 2FA credentials for a user.
	// Payload: *DisableBeforeEventPayload
	EventDisableBefore = "twofactor:disable:before"

	// EventDisableAfter is emitted after 2FA credentials have been removed from storage.
	// Payload: *DisableAfterEventPayload
	EventDisableAfter = "twofactor:disable:after"

	// EventVerifySuccess is emitted after any successful 2FA verification (TOTP, Backup Code, OTP, Challenge).
	// Payload: *VerifySuccessEventPayload
	EventVerifySuccess = "twofactor:verify:success"

	// EventVerifyFailed is emitted after any failed 2FA verification attempt.
	// Payload: *VerifyFailedEventPayload
	EventVerifyFailed = "twofactor:verify:failed"

	// EventSendOTPBefore is emitted before generating and sending an SMS/Email OTP challenge.
	// Payload: *SendOTPBeforeEventPayload
	EventSendOTPBefore = "twofactor:send_otp:before"

	// EventSendOTPAfter is emitted after an OTP challenge has been successfully dispatched.
	// Payload: *SendOTPAfterEventPayload
	EventSendOTPAfter = "twofactor:send_otp:after"

	// EventAccountLocked is emitted when 2FA verification is locked out due to excessive failed attempts.
	// Payload: *AccountLockedEventPayload
	EventAccountLocked = "twofactor:account:locked"

	// EventDeviceTrusted is emitted when a client device is authorized as a trusted device.
	// Payload: *DeviceTrustedEventPayload
	EventDeviceTrusted = "twofactor:device:trusted"

	// EventBackupCodesRegenerated is emitted after fresh single-use backup recovery codes are generated.
	// Payload: *BackupCodesRegeneratedEventPayload
	EventBackupCodesRegenerated = "twofactor:backup_codes:regenerated"

	// EventTOTPGenerated is emitted whenever a raw Base32 TOTP secret is created.
	// Payload: *TOTPGeneratedEventPayload
	EventTOTPGenerated = "twofactor:totp:generated"

	// EventChallengeCreated is emitted when a temporary sign-in 2FA challenge is issued.
	// Payload: *ChallengeCreatedEventPayload
	EventChallengeCreated = "twofactor:challenge:created"
)

// Typed Event Payloads

// EnableBeforeEventPayload contains the user ID and mutable parameters for pre-enrollment interception.
type EnableBeforeEventPayload struct {
	// UserID identifies the user beginning 2FA setup.
	UserID string

	// Params holds the mutable enrollment parameters (including dynamic Extra metadata).
	Params *EnableParams
}

// EnableAfterEventPayload contains confirmation details after 2FA secrets have been created.
type EnableAfterEventPayload struct {
	// UserID identifies the user whose 2FA enrollment completed.
	UserID string

	// BackupCodesCount is the number of single-use backup codes generated.
	BackupCodesCount int
}

// DisableBeforeEventPayload contains details before 2FA credentials are removed.
type DisableBeforeEventPayload struct {
	// UserID identifies the user whose 2FA configuration is being disabled.
	UserID string

	// Params holds the mutable disable parameters.
	Params *DisableParams
}

// DisableAfterEventPayload contains the user ID associated with a 2FA disablement event.
type DisableAfterEventPayload struct {
	// UserID identifies the user whose 2FA configuration was removed.
	UserID string
}

// VerifySuccessEventPayload reports details of a successful 2FA verification.
type VerifySuccessEventPayload struct {
	// UserID identifies the user who verified 2FA.
	UserID string

	// Method is the authentication method used ("totp", "backup_code", "otp").
	Method string

	// TrustDevice indicates if the device was trusted during verification.
	TrustDevice bool
}

// VerifyFailedEventPayload reports details of a failed verification attempt.
type VerifyFailedEventPayload struct {
	// UserID identifies the user attempting verification.
	UserID string

	// Method is the authentication method attempted ("totp", "backup_code", "otp").
	Method string

	// Failures is the current consecutive failed attempt count.
	Failures int
}

// SendOTPBeforeEventPayload contains details before an OTP challenge is created.
type SendOTPBeforeEventPayload struct {
	// UserID identifies the target user for the OTP challenge.
	UserID string

	// Params holds the parameters for sending OTP.
	Params *SendOTPParams
}

// SendOTPAfterEventPayload contains confirmation details after an OTP challenge has been dispatched.
type SendOTPAfterEventPayload struct {
	// UserID identifies the target user for the OTP challenge.
	UserID string

	// OTPCode is the generated numeric challenge code.
	OTPCode string

	// ExpiresAt specifies the exact expiration time for the OTP challenge.
	ExpiresAt time.Time
}

// AccountLockedEventPayload contains details when an account lockout is triggered.
type AccountLockedEventPayload struct {
	// UserID identifies the locked user.
	UserID string

	// Failures is the number of consecutive failed attempts triggering the lockout.
	Failures int

	// LockedUntil specifies the timestamp when the lockout expires.
	LockedUntil time.Time
}

// DeviceTrustedEventPayload contains details when a client device is authorized.
type DeviceTrustedEventPayload struct {
	// UserID identifies the device owner.
	UserID string

	// DeviceID identifies the trusted client hardware or installation.
	DeviceID string

	// ExpiresAt specifies when the device trust expires.
	ExpiresAt time.Time
}

// BackupCodesRegeneratedEventPayload contains confirmation when backup codes are regenerated.
type BackupCodesRegeneratedEventPayload struct {
	// UserID identifies the user whose codes were regenerated.
	UserID string

	// Amount is the number of new backup codes generated.
	Amount int
}

// TOTPGeneratedEventPayload contains the raw secret generated during 2FA setup.
type TOTPGeneratedEventPayload struct {
	// UserID identifies the user for whom the secret was created.
	UserID string

	// Secret is the Base32-encoded TOTP secret.
	Secret string
}

// ChallengeCreatedEventPayload contains details of an issued sign-in challenge.
type ChallengeCreatedEventPayload struct {
	// Token is the challenge token string.
	Token string

	// UserID identifies the target user.
	UserID string

	// ExpiresAt specifies when the challenge token expires.
	ExpiresAt time.Time
}
