package twofactor

// Standard Extra metadata keys that can be set or consumed in TwoFactor parameters
// (such as EnableParams.Extra, VerifyChallengeParams.Extra, and Event payloads).
const (
	// ExtraKeyTwoFactorMethod specifies the method used for 2FA (e.g. "totp", "backup_code", "otp", "sms", "email").
	ExtraKeyTwoFactorMethod = "two_factor_method"

	// ExtraKeyDeviceID represents the unique hardware or installation identifier of the client device.
	ExtraKeyDeviceID = "device_id"

	// ExtraKeyIPAddress represents the IP address of the client performing 2FA enrollment or verification.
	ExtraKeyIPAddress = "ip_address"

	// ExtraKeyUserAgent represents the User-Agent header of the client device during 2FA operations.
	ExtraKeyUserAgent = "user_agent"

	// ExtraKeyTrustDevice indicates whether the client requests trusting the current device to bypass subsequent 2FA challenges.
	ExtraKeyTrustDevice = "trust_device"

	// ExtraKeyTrustDeviceToken represents the cryptographic HMAC token issued to an authorized trusted device.
	ExtraKeyTrustDeviceToken = "trust_device_token"

	// ExtraKeySessionID represents the session ID associated with the 2FA authentication flow.
	ExtraKeySessionID = "session_id"

	// ExtraKeyIssuer overrides the default application issuer name shown in authenticator apps.
	ExtraKeyIssuer = "issuer"

	// ExtraKeyPhoneNumber represents the destination phone number for SMS OTP challenges.
	ExtraKeyPhoneNumber = "phone_number"

	// ExtraKeyEmail represents the destination email address for Email OTP challenges.
	ExtraKeyEmail = "email"

	// ExtraKeyChallengeToken represents the temporary challenge token issued following a primary sign-in.
	ExtraKeyChallengeToken = "challenge_token"

	// ExtraKeyTwoFactorVerified indicates if two-factor verification succeeded.
	ExtraKeyTwoFactorVerified = "two_factor_verified"
)

// Supported two-factor authentication method constants.
const (
	// MethodTOTP represents Time-based One-Time Password authentication (RFC 6238).
	MethodTOTP = "totp"

	// MethodBackupCode represents single-use recovery backup codes.
	MethodBackupCode = "backup_code"

	// MethodOTP represents challenge-based one-time password verification.
	MethodOTP = "otp"

	// MethodSMS represents SMS-delivered OTP challenges.
	MethodSMS = "sms"

	// MethodEmail represents Email-delivered OTP challenges.
	MethodEmail = "email"
)

// Context keys stored in plugin.Context for TwoFactor state management.
const (
	// ContextKeyTwoFactorPendingPrefix is the key prefix indicating a pending 2FA challenge for a user.
	ContextKeyTwoFactorPendingPrefix = "2fa_pending_"

	// ContextKeyTwoFactorVerifiedPrefix is the key prefix indicating verified 2FA status for a user.
	ContextKeyTwoFactorVerifiedPrefix = "2fa_verified_"

	// ContextKeyTwoFactorMethodPrefix is the key prefix indicating the active 2FA method for a user.
	ContextKeyTwoFactorMethodPrefix = "2fa_method_"

	// ContextKeyTwoFactorChallengePrefix is the key prefix for temporary challenge tokens.
	ContextKeyTwoFactorChallengePrefix = "2fa_challenge_"
)

// TwoFactorPendingKey formats the context store key used to track a pending 2FA verification for the given user.
func TwoFactorPendingKey(userID string) string {
	return ContextKeyTwoFactorPendingPrefix + userID
}

// TwoFactorVerifiedKey formats the context store key used to track a completed 2FA verification for the given user.
func TwoFactorVerifiedKey(userID string) string {
	return ContextKeyTwoFactorVerifiedPrefix + userID
}

// TwoFactorMethodKey formats the context store key used to track the active 2FA method for the given user.
func TwoFactorMethodKey(userID string) string {
	return ContextKeyTwoFactorMethodPrefix + userID
}

// TwoFactorChallengeKey formats the context store key used to cache challenge tokens.
func TwoFactorChallengeKey(token string) string {
	return ContextKeyTwoFactorChallengePrefix + token
}
