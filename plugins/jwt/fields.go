package jwt

// Standard Extra metadata keys that can be set or consumed in JWT operations
// (such as in SignParams.Extra, VerifyParams.Extra, and Event payloads).
const (
	// ExtraKeySubject stores the subject identifier ("sub") within dynamic Extra metadata.
	// Expected type: string.
	ExtraKeySubject = "subject"

	// ExtraKeyClaims stores custom claims map within dynamic Extra metadata.
	// Expected type: map[string]any.
	ExtraKeyClaims = "claims"

	// ExtraKeyKeyID stores the active Key ID ("kid") within dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyKeyID = "key_id"

	// ExtraKeySessionID stores the associated session identifier within dynamic Extra metadata.
	// Expected type: string.
	ExtraKeySessionID = "session_id"

	// ExtraKeyUserID stores the owner user identifier within dynamic Extra metadata.
	// Expected type: string.
	ExtraKeyUserID = "user_id"

	// ExtraKeyTokenSource identifies the extraction origin of the token (e.g., "header", "cookie", "param").
	// Expected type: string.
	ExtraKeyTokenSource = "token_source"
)

// Supported JSON Web Signature (JWS) algorithm identifiers.
const (
	// AlgEdDSA represents Ed25519 signature algorithm (RFC 8037 / RFC 8032) - default.
	AlgEdDSA Algorithm = "EdDSA"

	// AlgES256 represents ECDSA using P-256 curve and SHA-256 (RFC 7518).
	AlgES256 Algorithm = "ES256"

	// AlgES512 represents ECDSA using P-521 curve and SHA-512 (RFC 7518).
	AlgES512 Algorithm = "ES512"

	// AlgRS256 represents RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518).
	AlgRS256 Algorithm = "RS256"

	// AlgPS256 represents RSASSA-PSS using SHA-256 and MGF1 (RFC 7518).
	AlgPS256 Algorithm = "PS256"
)

// Standard HTTP header and authentication scheme constants.
const (
	// HeaderAuthorization is the standard RFC 7235 HTTP Authorization header name.
	HeaderAuthorization = "Authorization"

	// HeaderSetAuthJWT is the default HTTP response header name used to expose the issued JWT.
	HeaderSetAuthJWT = "set-auth-jwt"

	// HeaderAccessControlExposeHeaders is the standard CORS response header used to expose custom headers to client browsers.
	HeaderAccessControlExposeHeaders = "Access-Control-Expose-Headers"

	// BearerSchemePrefix is the standard case-insensitive scheme prefix preceding bearer tokens in Authorization headers.
	BearerSchemePrefix = "bearer "
)

// Shared plugin context keys used for internal state and JWK caching in plugin.Context.
const (
	// ContextKeyJWKPrefix is the key prefix used when caching active JWK keys in plugin.Context.
	ContextKeyJWKPrefix = "jwt:jwk:"
)

// JWKCacheKey formats the context store key used to track or cache a JWK key in the shared context.
func JWKCacheKey(kid string) string {
	return ContextKeyJWKPrefix + kid
}
