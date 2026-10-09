package oidc

import "errors"

var (
	// ErrProviderNotFound indicates that the requested OIDC provider is not configured.
	ErrProviderNotFound = errors.New("oidc: provider not found")

	// ErrInvalidInput indicates that mandatory input fields were missing or malformed.
	ErrInvalidInput = errors.New("oidc: invalid input")

	// ErrInvalidState indicates that the returned state parameter did not match any stored session.
	ErrInvalidState = errors.New("oidc: invalid state token")

	// ErrStateExpired indicates that the state session has passed its expiration window.
	ErrStateExpired = errors.New("oidc: state token expired")

	// ErrStateConsumed indicates that the state session was already redeemed (replay attack prevented).
	ErrStateConsumed = errors.New("oidc: state token already consumed")

	// ErrMissingIDToken indicates that the token response omitted the required id_token field.
	ErrMissingIDToken = errors.New("oidc: missing id_token in token response")

	// ErrInvalidIDToken indicates that the ID token string was malformed or could not be parsed.
	ErrInvalidIDToken = errors.New("oidc: malformed id_token")

	// ErrSignatureInvalid indicates that the cryptographic JWS signature verification failed.
	ErrSignatureInvalid = errors.New("oidc: id_token signature verification failed")

	// ErrIssuerMismatch indicates that the ID token issuer (iss) did not match the configured provider issuer.
	ErrIssuerMismatch = errors.New("oidc: issuer claim mismatch")

	// ErrAudienceMismatch indicates that the ID token audience (aud) did not include the client_id.
	ErrAudienceMismatch = errors.New("oidc: audience claim mismatch")

	// ErrNonceMismatch indicates that the ID token nonce claim did not match the expected state nonce.
	ErrNonceMismatch = errors.New("oidc: nonce claim mismatch")

	// ErrTokenExpired indicates that the ID token has expired (exp claim in the past).
	ErrTokenExpired = errors.New("oidc: id_token has expired")

	// ErrKeyNotFound indicates that the signing key (kid) could not be located in the provider JWKS set.
	ErrKeyNotFound = errors.New("oidc: signing key not found in jwks")

	// ErrAccountConflict indicates an email collision where linking is disallowed.
	ErrAccountConflict = errors.New("oidc: an account with this email already exists")

	// ErrAccountLinkingRequiresConsent indicates that linking requires explicit user approval.
	ErrAccountLinkingRequiresConsent = errors.New("oidc: account linking requires user consent")

	// ErrUnverifiedEmailLinkingProhibited indicates that linking was refused because an email is unverified.
	ErrUnverifiedEmailLinkingProhibited = errors.New("oidc: cannot link account with unverified email")

	// ErrCannotUnlinkSoleAuthMethod indicates refusal to unlink the user's only remaining login credential.
	ErrCannotUnlinkSoleAuthMethod = errors.New("oidc: cannot unlink sole authentication method")

	// ErrDiscoveryFailed indicates that OpenID Connect Discovery (.well-known/openid-configuration) failed.
	ErrDiscoveryFailed = errors.New("oidc: provider discovery failed")
)
