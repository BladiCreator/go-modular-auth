package sso

import "errors"

var (
	// ErrConfigNotFound indicates that the requested SSO configuration does not exist.
	ErrConfigNotFound = errors.New("sso: configuration not found")

	// ErrConfigDisabled indicates that the target SSO configuration is currently inactive.
	ErrConfigDisabled = errors.New("sso: configuration is disabled")

	// ErrDomainNotFound indicates that no organization SSO provider claims the specified domain.
	ErrDomainNotFound = errors.New("sso: domain not registered for sso")

	// ErrDomainConflict indicates that the domain is already claimed by another organization.
	ErrDomainConflict = errors.New("sso: domain is already claimed by another organization")

	// ErrInvalidInput indicates missing or malformed required parameters.
	ErrInvalidInput = errors.New("sso: invalid input")

	// ErrInvalidProtocol indicates an unsupported federation protocol.
	ErrInvalidProtocol = errors.New("sso: invalid or unsupported protocol")

	// ErrInvalidState indicates that the returned state token does not match any in-flight session.
	ErrInvalidState = errors.New("sso: invalid state token")

	// ErrStateExpired indicates that the in-flight SSO transaction has expired.
	ErrStateExpired = errors.New("sso: state token expired")

	// ErrStateConsumed indicates that the state session was already redeemed (replay attack prevented).
	ErrStateConsumed = errors.New("sso: state token already consumed")

	// ErrCrossTenantViolation indicates an attempted cross-tenant identity injection or mismatch.
	ErrCrossTenantViolation = errors.New("sso: cross-tenant identity confusion detected")

	// ErrJITDisabled indicates that Just-In-Time provisioning is disabled and the user does not exist.
	ErrJITDisabled = errors.New("sso: just-in-time provisioning is disabled for this organization")

	// ErrAccountConflict indicates an email or identity collision where linking is disallowed.
	ErrAccountConflict = errors.New("sso: an account with this email already exists and auto-link is disabled")

	// ErrUnverifiedEmail indicates that the IdP did not assert email verification or domain mismatch.
	ErrUnverifiedEmail = errors.New("sso: unverified email or domain mismatch")

	// ErrMissingEmailAttribute indicates that no email address could be extracted from the assertion.
	ErrMissingEmailAttribute = errors.New("sso: assertion is missing required email attribute")

	// ErrIdPValidationFailed indicates that the Identity Provider configuration failed sanity checks.
	ErrIdPValidationFailed = errors.New("sso: identity provider configuration validation failed")

	// ErrSAMLResponseInvalid indicates that the SAML Response XML was malformed or missing required assertions.
	ErrSAMLResponseInvalid = errors.New("sso: malformed saml response")

	// ErrSAMLSignatureInvalid indicates that the cryptographic signature verification of the SAML assertion failed.
	ErrSAMLSignatureInvalid = errors.New("sso: saml assertion signature verification failed")

	// ErrSAMLAudienceMismatch indicates that the SAML assertion AudienceRestriction does not match SP Entity ID.
	ErrSAMLAudienceMismatch = errors.New("sso: saml audience restriction mismatch")

	// ErrSAMLExpired indicates that the SAML assertion is outside its NotBefore/NotOnOrAfter validity window.
	ErrSAMLExpired = errors.New("sso: saml assertion validity window expired")

	// ErrOIDCValidationFailed indicates that OIDC token exchange or ID Token validation failed.
	ErrOIDCValidationFailed = errors.New("sso: oidc token validation failed")
)
