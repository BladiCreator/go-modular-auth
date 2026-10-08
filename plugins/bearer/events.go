package bearer

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventBearerTokenIssued is emitted when a new bearer token has been successfully generated and persisted.
	EventBearerTokenIssued auth.EventName = "bearer.token.issued"

	// EventBearerTokenRevoked is emitted when an existing bearer token is revoked.
	EventBearerTokenRevoked auth.EventName = "bearer.token.revoked"

	// EventBearerAuthenticated is emitted when a bearer token is successfully authenticated.
	EventBearerAuthenticated auth.EventName = "bearer.authenticated"

	// EventBearerTokenExpired is emitted when an authentication attempt encounters an expired token.
	EventBearerTokenExpired auth.EventName = "bearer.token.expired"
)

// TokenIssuedPayload carries metadata about an issued token.
// The plaintext token secret and its hash are NEVER included in events.
type TokenIssuedPayload struct {
	TokenID       string             `json:"token_id"`
	Subject       string             `json:"subject"`
	PrincipalType auth.PrincipalType `json:"principal_type"`
	Scopes        []string           `json:"scopes"`
	ExpiresAt     time.Time          `json:"expires_at"`
	CreatedAt     time.Time          `json:"created_at"`
}

// TokenRevokedPayload carries metadata about a token revocation event.
type TokenRevokedPayload struct {
	TokenID   string    `json:"token_id,omitempty"`
	Subject   string    `json:"subject"`
	RevokedAt time.Time `json:"revoked_at"`
}

// AuthenticatedPayload carries diagnostic metadata about a successful authentication.
type AuthenticatedPayload struct {
	TokenID       string             `json:"token_id"`
	Subject       string             `json:"subject"`
	PrincipalType auth.PrincipalType `json:"principal_type"`
	Time          time.Time          `json:"time"`
}

// TokenExpiredPayload carries diagnostic metadata when an expired token is presented.
type TokenExpiredPayload struct {
	TokenID   string    `json:"token_id"`
	Subject   string    `json:"subject"`
	ExpiresAt time.Time `json:"expires_at"`
	Time      time.Time `json:"time"`
}
