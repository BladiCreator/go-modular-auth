package bearer

import (
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

const (
	// EventBearerVerifyBefore is emitted right before starting token verification.
	// Payload: *BearerVerifyBeforeEventPayload
	EventBearerVerifyBefore = "bearer:verify:before"

	// EventBearerVerifyAfter is emitted after completing token cryptographic verification.
	// Payload: *BearerVerifyAfterEventPayload
	EventBearerVerifyAfter = "bearer:verify:after"

	// EventBearerTokenCreated is emitted when a new signed bearer token is created.
	// Payload: *BearerTokenCreatedEventPayload
	EventBearerTokenCreated = "bearer:token:created"
)

// BearerVerifyBeforeEventPayload contains pre-verification data for lifecycle interception.
type BearerVerifyBeforeEventPayload struct {
	// RawToken is the incoming token string before signature verification.
	RawToken string

	// Params contains the mutable verification parameters (including Extra metadata).
	Params *VerifyParams
}

// BearerVerifyAfterEventPayload reports the result of a token validation attempt.
type BearerVerifyAfterEventPayload struct {
	// Token is the processed token string.
	Token string

	// Valid indicates whether the signature and format were valid.
	Valid bool

	// Session contains the retrieved session entity if resolved via repository (optional).
	Session *entity.Session
}

// BearerTokenCreatedEventPayload contains the details of a newly created and signed token.
type BearerTokenCreatedEventPayload struct {
	// RawToken is the base unsigned token identifier.
	RawToken string

	// SignedToken is the resulting HMAC-SHA256 signed token in base64url format.
	SignedToken string

	// UserID identifies the owner user ID (if available).
	UserID string
}
