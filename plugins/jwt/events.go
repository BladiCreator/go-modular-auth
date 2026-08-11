package jwt

import (
	"time"
)

const (
	// EventJWTSignBefore is emitted immediately before a JWT is constructed and signed.
	// Payload: *JWTSignBeforeEventPayload
	EventJWTSignBefore = "jwt:sign:before"

	// EventJWTSignAfter is emitted after a JWT has been successfully signed.
	// Payload: *JWTSignAfterEventPayload
	EventJWTSignAfter = "jwt:sign:after"

	// EventJWTVerifyBefore is emitted right before token verification begins.
	// Payload: *JWTVerifyBeforeEventPayload
	EventJWTVerifyBefore = "jwt:verify:before"

	// EventJWTVerifyAfter is emitted after token verification completes.
	// Payload: *JWTVerifyAfterEventPayload
	EventJWTVerifyAfter = "jwt:verify:after"

	// EventJWTRotateBefore is emitted before rotating key pairs.
	// Payload: *JWTRotateBeforeEventPayload
	EventJWTRotateBefore = "jwt:rotate:before"

	// EventJWTRotateAfter is emitted after a new key pair has been generated and persisted.
	// Payload: *JWTRotateAfterEventPayload
	EventJWTRotateAfter = "jwt:rotate:after"

	// EventJWTIssued is emitted when a new JWT is issued for an authenticated session.
	// Payload: *JWTIssuedEventPayload
	EventJWTIssued = "jwt:token:issued"
)

// JWTSignBeforeEventPayload contains payload data for pre-signing lifecycle interception.
type JWTSignBeforeEventPayload struct {
	// Params contains the mutable signing parameters (including Extra metadata).
	Params *SignParams

	// Subject is the resolved subject string ("sub").
	Subject string

	// Claims contains mutable custom payload claims.
	Claims map[string]any
}

// JWTSignAfterEventPayload contains the resulting token details after signing.
type JWTSignAfterEventPayload struct {
	// Token is the serialized compact JWT string.
	Token string

	// KeyID is the ID of the key used to sign the token.
	KeyID string

	// Algorithm is the cryptographic algorithm used.
	Algorithm Algorithm

	// ExpiresAt is the token expiration timestamp.
	ExpiresAt time.Time
}

// JWTVerifyBeforeEventPayload contains pre-verification token data.
type JWTVerifyBeforeEventPayload struct {
	// Token is the raw JWT string to verify.
	Token string

	// Params contains mutable verification parameters.
	Params *VerifyParams
}

// JWTVerifyAfterEventPayload reports the result of a token verification attempt.
type JWTVerifyAfterEventPayload struct {
	// Token is the processed JWT string.
	Token string

	// Valid indicates whether the token signature and standard claims were valid.
	Valid bool

	// KeyID is the key ID extracted from the token header.
	KeyID string

	// Claims contains the unmarshaled payload claims (if valid).
	Claims map[string]any

	// Error contains the verification failure reason (if invalid).
	Error error
}

// JWTRotateBeforeEventPayload contains parameters prior to key rotation.
type JWTRotateBeforeEventPayload struct {
	// CurrentKeyID is the active key ID being rotated out.
	CurrentKeyID string

	// Params contains rotation configuration parameters.
	Params *RotateKeysParams
}

// JWTRotateAfterEventPayload contains details of the newly generated key pair.
type JWTRotateAfterEventPayload struct {
	// NewKeyID is the identifier of the newly active key.
	NewKeyID string

	// Algorithm is the cryptographic algorithm of the new key.
	Algorithm Algorithm

	// CreatedAt is the timestamp when the new key was created.
	CreatedAt time.Time
}

// JWTIssuedEventPayload contains metadata when a JWT is issued for a session.
type JWTIssuedEventPayload struct {
	// Token is the issued compact JWT string.
	Token string

	// KeyID is the key identifier used for the signature.
	KeyID string

	// Subject is the "sub" claim value.
	Subject string

	// SessionID is the associated session identifier (if applicable).
	SessionID string

	// UserID is the associated user identifier (if applicable).
	UserID string
}
