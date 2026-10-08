package jwt

import (
	"context"
	"time"
)

// JWT defines the capability contract exposed by the JWT plugin module.
// Applications access it via auth.Get[plugins.JWT]().
type JWT interface {
	// Issue signs and issues a new JWT token using the active signing key.
	Issue(ctx context.Context, claims Claims) (string, error)

	// IssueWithKey signs and issues a new JWT token using a specific key identifier (kid).
	IssueWithKey(ctx context.Context, keyID string, claims Claims) (string, error)

	// Verify parses the token, validates the cryptographic signature, validates standard claims
	// (iss, aud, sub, exp, nbf), prevents algorithm confusion, and checks revocation if configured.
	Verify(ctx context.Context, tokenString string, opts ...VerifyOption) (*Claims, error)

	// Revoke invalidates a specific token identifier (jti) until its expiration time.
	Revoke(ctx context.Context, jti string, expiresAt time.Time, reason string) error

	// RevokeSubject invalidates all tokens issued to the given subject before the specified cutoff timestamp.
	RevokeSubject(ctx context.Context, subject string, cutoff time.Time, reason string) error

	// IsRevoked checks if a token or subject has been marked as revoked.
	IsRevoked(ctx context.Context, jti string, subject string, issuedAt time.Time) (bool, error)

	// JWKS exports the public keys formatted as an RFC 7517 JSON Web Key Set.
	JWKS(ctx context.Context) (*JWKS, error)

	// Keys returns the active KeyManager for key registration and rotation.
	Keys() KeyManager
}

type verifyConfig struct {
	expectedIssuer   string
	expectedAudience string
	expectedSubject  string
	leeway           time.Duration
	requiredClaims   []string
}

// VerifyOption configures claim validation parameters for Verify.
type VerifyOption func(*verifyConfig)

// WithExpectedIssuer asserts that the token's iss claim matches expected.
func WithExpectedIssuer(expected string) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.expectedIssuer = expected
	}
}

// WithExpectedAudience asserts that the token's aud claim contains expected.
func WithExpectedAudience(expected string) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.expectedAudience = expected
	}
}

// WithExpectedSubject asserts that the token's sub claim matches expected.
func WithExpectedSubject(expected string) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.expectedSubject = expected
	}
}

// WithLeeway allows clock skew tolerance when validating exp and nbf timestamps.
func WithLeeway(leeway time.Duration) VerifyOption {
	return func(cfg *verifyConfig) {
		if leeway > 0 {
			cfg.leeway = leeway
		}
	}
}

// WithRequiredClaims asserts that all specified claims are present in the token payload.
func WithRequiredClaims(claims ...string) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.requiredClaims = append(cfg.requiredClaims, claims...)
	}
}
