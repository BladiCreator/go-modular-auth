package jwt

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
)

const (
	// EventJWTTokenIssued is emitted when a new JWT has been signed and issued.
	EventJWTTokenIssued auth.EventName = "jwt.token.issued"

	// EventJWTTokenVerified is emitted when a token is successfully verified.
	EventJWTTokenVerified auth.EventName = "jwt.token.verified"

	// EventJWTTokenRevoked is emitted when a token or subject is explicitly revoked.
	EventJWTTokenRevoked auth.EventName = "jwt.token.revoked"

	// EventJWTKeyRotated is emitted when the active signing key is rotated.
	EventJWTKeyRotated auth.EventName = "jwt.key.rotated"
)

// TokenIssuedPayload carries diagnostic metadata about an issued token.
// Cryptographic keys, signatures, and sensitive claims are strictly omitted.
type TokenIssuedPayload struct {
	KeyID     string    `json:"key_id"`
	JTI       string    `json:"jti,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Audience  []string  `json:"audience,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
}

// TokenVerifiedPayload carries diagnostic metadata about a verified token.
type TokenVerifiedPayload struct {
	KeyID   string    `json:"key_id"`
	JTI     string    `json:"jti,omitempty"`
	Subject string    `json:"subject,omitempty"`
	Issuer  string    `json:"issuer,omitempty"`
	Time    time.Time `json:"time"`
}

// TokenRevokedPayload carries metadata about a revocation event.
type TokenRevokedPayload struct {
	JTI       string    `json:"jti,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
}

// KeyRotatedPayload carries metadata when a key rotation occurs.
type KeyRotatedPayload struct {
	PreviousKeyID string    `json:"previous_key_id,omitempty"`
	NewKeyID      string    `json:"new_key_id"`
	Algorithm     Algorithm `json:"algorithm"`
	Time          time.Time `json:"time"`
}
