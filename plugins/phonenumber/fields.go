// Package phonenumber provides SMS OTP (One-Time Password) and phone number-based authentication
// for go-modular-auth, supporting passwordless sign-in, phone number verification and updates,
// phone + password login, SMS password resets, and attempt budgeting.
package phonenumber

import (
	"fmt"
	"strings"
)

// OTPType defines the valid types of OTP operations supported by the Phone Number plugin.
type OTPType string

const (
	// OTPTypeVerification represents phone number verification or passwordless sign-in via OTP.
	OTPTypeVerification OTPType = "phone-verification"

	// OTPTypePasswordReset represents password recovery and reset via phone OTP.
	OTPTypePasswordReset OTPType = "phone-password-reset"
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

// Standard Extra metadata keys that can be set or consumed in Phone Number parameters and Event payloads.
const (
	ExtraKeyPhoneNumber         = "phone_number"
	ExtraKeyPhoneNumberVerified = "phone_number_verified"
	ExtraKeyOTPCode             = "otp_code"
	ExtraKeyOTPType             = "otp_type"
	ExtraKeyRememberMe          = "remember_me"
	ExtraKeyUpdatePhone         = "update_phone_number"
	ExtraKeyDisableSession      = "disable_session"
	ExtraKeyDeviceID            = "device_id"
	ExtraKeyIPAddress           = "ip_address"
	ExtraKeyUserAgent           = "user_agent"
)

// ToOTPIdentifier formats the standard storage identifier for phone verification or sign-in OTP.
// Format: "phone-verification-otp-<normalized_phone>"
func ToOTPIdentifier(phoneNumber string) string {
	return fmt.Sprintf("phone-verification-otp-%s", strings.TrimSpace(phoneNumber))
}

// ToPasswordResetOTPIdentifier formats the storage identifier for SMS password reset OTP.
// Format: "phone-password-reset-otp-<normalized_phone>"
func ToPasswordResetOTPIdentifier(phoneNumber string) string {
	return fmt.Sprintf("phone-password-reset-otp-%s", strings.TrimSpace(phoneNumber))
}

// SplitAtLastColon splits a stored value string into the stored OTP payload and the attempt counter ("<stored_otp>:<attempts>").
func SplitAtLastColon(input string) (string, string) {
	idx := strings.LastIndex(input, ":")
	if idx == -1 {
		return input, "0"
	}
	return input[:idx], input[idx+1:]
}
