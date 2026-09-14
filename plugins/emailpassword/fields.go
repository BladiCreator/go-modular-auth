package emailpassword

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
