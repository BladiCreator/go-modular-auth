package bearer

// Standard Extra metadata keys that can be set or consumed in Bearer operations
// (such as in VerifyParams.Extra, CreateTokenParams.Extra, and Event payloads).
const (
	// ExtraKeyRawToken stores the raw unsigned token string within dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyRawToken = "raw_token"

	// ExtraKeySignedToken stores the HMAC-signed token string within dynamic Extra metadata.
	// Expected type: string.
	ExtraKeySignedToken = "signed_token"

	// ExtraKeySessionID stores the resolved session ID within dynamic Extra metadata.
	// Expected type: string.
	ExtraKeySessionID = "session_id"

	// ExtraKeyUserID stores the owner user ID within dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyUserID = "user_id"

	// ExtraKeyTokenSource identifies the extraction origin of the token (e.g. "header", "query", "body").
	// Expected type: string.
	ExtraKeyTokenSource = "token_source"
)

// Standard HTTP header and authentication scheme constants.
const (
	// HeaderAuthorization is the standard RFC 7235 HTTP Authorization header name.
	HeaderAuthorization = "Authorization"

	// HeaderSetAuthToken is the default HTTP response header name used to expose the issued bearer token.
	HeaderSetAuthToken = "set-auth-token"

	// HeaderAccessControlExposeHeaders is the standard CORS response header used to expose custom headers to client browsers.
	HeaderAccessControlExposeHeaders = "Access-Control-Expose-Headers"

	// BearerSchemePrefix is the standard case-insensitive scheme prefix preceding bearer tokens in Authorization headers.
	BearerSchemePrefix = "bearer "
)

// Shared plugin context keys used for internal state and token caching in plugin.Context.
const (
	// ContextKeyTokenPrefix is the key prefix used when caching validated tokens in plugin.Context.
	ContextKeyTokenPrefix = "bearer:token:"
)

// BearerTokenCacheKey formats the context store key used to track or cache a validated token in the shared context.
func BearerTokenCacheKey(token string) string {
	return ContextKeyTokenPrefix + token
}
