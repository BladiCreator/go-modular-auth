package plugin

// Standard context key constants stored in the shared thread-safe plugin.Context store.
const (
	// ContextKeyUser stores the current authenticated user domain entity.
	ContextKeyUser = "auth:user"

	// ContextKeySession stores the active session domain entity.
	ContextKeySession = "auth:session"

	// ContextKeyAccount stores the active account entity.
	ContextKeyAccount = "auth:account"

	// ContextKeyBearerToken stores the bearer or access token string.
	ContextKeyBearerToken = "auth:bearer_token"
)
