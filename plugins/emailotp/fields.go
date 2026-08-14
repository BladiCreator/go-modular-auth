// Package emailotp provides email-based One-Time Password (OTP) authentication for go-modular-auth,
// supporting passwordless sign-in, email verification, password reset, and email change flows.
package emailotp

import (
	"fmt"
	"strings"
)

// OTPType defines the valid types of OTP operations supported by the plugin.
type OTPType string

const (
	// OTPTypeEmailVerification represents email address ownership verification.
	OTPTypeEmailVerification OTPType = "email-verification"

	// OTPTypeSignIn represents passwordless sign-in or auto-registration via OTP.
	OTPTypeSignIn OTPType = "sign-in"

	// OTPTypeForgetPassword represents password recovery and reset.
	OTPTypeForgetPassword OTPType = "forget-password"

	// OTPTypeChangeEmail represents changing a user's verified email address.
	OTPTypeChangeEmail OTPType = "change-email"
)

// StoreOTPMode defines how the OTP code is persisted in storage.
type StoreOTPMode string

const (
	// StoreOTPPlain stores the OTP code in plain text.
	StoreOTPPlain StoreOTPMode = "plain"

	// StoreOTPHashed stores the OTP code using constant-time SHA-256 hash.
	StoreOTPHashed StoreOTPMode = "hashed"

	// StoreOTPEncrypted stores the OTP code using AES-256-GCM symmetric encryption.
	StoreOTPEncrypted StoreOTPMode = "encrypted"
)

// ResendStrategy defines the behavior when requesting a new OTP while an active one exists.
type ResendStrategy string

const (
	// ResendStrategyRotate always invalidates the previous OTP and generates a fresh code.
	ResendStrategyRotate ResendStrategy = "rotate"

	// ResendStrategyReuse resends the existing active OTP and extends its expiration (plain/encrypted only).
	ResendStrategyReuse ResendStrategy = "reuse"
)

// Standard Extra metadata keys that can be set or consumed in Email OTP parameters and Event payloads.
const (
	ExtraKeyOTPType      = "email_otp_type"
	ExtraKeyOTPEmail     = "email_otp_email"
	ExtraKeyOTPNewEmail  = "email_otp_new_email"
	ExtraKeyDeviceID     = "device_id"
	ExtraKeyIPAddress    = "ip_address"
	ExtraKeyUserAgent    = "user_agent"
	ExtraKeySessionToken = "session_token"
	ExtraKeyAutoSignIn   = "auto_sign_in"
)

// Context keys stored in plugin.Context for Email OTP state management.
const (
	ContextKeyEmailOTPPendingPrefix  = "email_otp_pending_"
	ContextKeyEmailOTPVerifiedPrefix = "email_otp_verified_"
)

// ToOTPIdentifier formats the standard storage identifier for an OTP given its type and email.
// Format: "<type>-otp-<normalized_email>" (e.g. "email-verification-otp-user@example.com")
func ToOTPIdentifier(otpType OTPType, email string) string {
	return fmt.Sprintf("%s-otp-%s", string(otpType), strings.ToLower(strings.TrimSpace(email)))
}

// ToChangeEmailOTPIdentifier formats the composite storage identifier for email change.
// Format: "change-email-otp-<normalized_current_email>-<normalized_new_email>"
func ToChangeEmailOTPIdentifier(currentEmail, newEmail string) string {
	return fmt.Sprintf("%s-otp-%s-%s",
		string(OTPTypeChangeEmail),
		strings.ToLower(strings.TrimSpace(currentEmail)),
		strings.ToLower(strings.TrimSpace(newEmail)),
	)
}

// SplitAtLastColon splits a stored value string into the stored OTP payload and the attempt counter ("<stored_otp>:<attempts>").
func SplitAtLastColon(input string) (string, string) {
	idx := strings.LastIndex(input, ":")
	if idx == -1 {
		return input, "0"
	}
	return input[:idx], input[idx+1:]
}
