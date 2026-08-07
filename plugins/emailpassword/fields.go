package emailpassword

// Standard Extra metadata keys that can be set or consumed during EmailPassword operations
// (such as in EventSignUpBefore, EventSignUpAfter, and CreateUserParams).
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

	// ExtraKeyAvatar represents the avatar image URL for the newly registered user.
	ExtraKeyAvatar = "avatar"

	// ExtraKeyLocale represents the preferred language/locale code of the user.
	ExtraKeyLocale = "locale"

	// ExtraKeyPermissions represents initial permissions assigned to the user.
	ExtraKeyPermissions = "permissions"

	// ExtraKeyMetadata represents arbitrary structured user metadata.
	ExtraKeyMetadata = "metadata"

	// ExtraKeyIsAnonymous indicates whether the registered account is a temporary/anonymous account.
	ExtraKeyIsAnonymous = "is_anonymous"
)

// Shared plugin context keys used for internal state management.
const (
	// ContextKeyVerificationTokenPrefix is the prefix used when caching email verification tokens in plugin.Context.
	ContextKeyVerificationTokenPrefix = "emailpassword:verification_token:"

	// ContextKeyResetTokenPrefix is the prefix used when caching password reset tokens in plugin.Context.
	ContextKeyResetTokenPrefix = "emailpassword:reset_token:"
)
