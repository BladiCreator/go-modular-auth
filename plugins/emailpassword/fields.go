package emailpassword

// Standard Extra metadata keys that can be set or consumed in EmailPassword parameters and events
// (such as SignUpParams.Extra, SignInParams.Extra, and Event payloads).
const (
	// ExtraKeyRole represents the user's assigned role during registration (e.g. "admin", "user").
	ExtraKeyRole = "role"

	// ExtraKeyOrganizationID represents the unique identifier of the organization to assign the user to.
	ExtraKeyOrganizationID = "organization_id"

	// ExtraKeyOrgID is a shorthand alias for ExtraKeyOrganizationID.
	ExtraKeyOrgID = "org_id"

	// ExtraKeyPhone represents the user's contact phone number.
	ExtraKeyPhone = "phone"

	// ExtraKeyPhoneNumber is an alias for ExtraKeyPhone.
	ExtraKeyPhoneNumber = "phone_number"

	// ExtraKeyAvatar represents the avatar image URL for the user.
	ExtraKeyAvatar = "avatar"

	// ExtraKeyLocale represents the preferred language/locale code of the user (e.g. "en-US", "es-ES").
	ExtraKeyLocale = "locale"

	// ExtraKeyPermissions represents initial permissions assigned to the user.
	ExtraKeyPermissions = "permissions"

	// ExtraKeyMetadata represents arbitrary structured user metadata.
	ExtraKeyMetadata = "metadata"

	// ExtraKeyIsAnonymous indicates whether the registered account is a temporary or anonymous account.
	ExtraKeyIsAnonymous = "is_anonymous"

	// ExtraKeyDeviceID represents the unique hardware or client installation identifier.
	ExtraKeyDeviceID = "device_id"

	// ExtraKeyIPAddress represents the client IP address initiating the authentication request.
	ExtraKeyIPAddress = "ip_address"

	// ExtraKeyUserAgent represents the User-Agent header of the client device.
	ExtraKeyUserAgent = "user_agent"

	// ExtraKeyCallbackURL represents the redirect or callback URL for verification or reset links.
	ExtraKeyCallbackURL = "callback_url"
)

// Shared plugin context keys stored in plugin.Context for transient state management.
const (
	// ContextKeyVerificationTokenPrefix is the prefix used when caching email verification tokens in plugin.Context.
	ContextKeyVerificationTokenPrefix = "emailpassword:verification_token:"

	// ContextKeyResetTokenPrefix is the prefix used when caching password reset tokens in plugin.Context.
	ContextKeyResetTokenPrefix = "emailpassword:reset_token:"
)

// VerificationTokenContextKey formats the context store key used to track an email verification token.
func VerificationTokenContextKey(token string) string {
	return ContextKeyVerificationTokenPrefix + token
}

// ResetTokenContextKey formats the context store key used to track a password reset token.
func ResetTokenContextKey(token string) string {
	return ContextKeyResetTokenPrefix + token
}
