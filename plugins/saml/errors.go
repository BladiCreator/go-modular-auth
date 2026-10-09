package saml

import "errors"

var (
	// ErrProviderNotFound indicates that the requested SAML Identity Provider is not registered.
	ErrProviderNotFound = errors.New("saml: identity provider not found")

	// ErrProviderDisabled indicates that the target IdP configuration is inactive.
	ErrProviderDisabled = errors.New("saml: identity provider is disabled")

	// ErrInvalidInput indicates missing or malformed required parameters.
	ErrInvalidInput = errors.New("saml: invalid input parameters")

	// ErrInvalidState indicates that the RelayState or InResponseTo did not match any stored session.
	ErrInvalidState = errors.New("saml: invalid or unknown request state")

	// ErrStateExpired indicates that the in-flight SAML authentication request has expired.
	ErrStateExpired = errors.New("saml: request session expired")

	// ErrStateConsumed indicates that the request state session was already redeemed.
	ErrStateConsumed = errors.New("saml: request session already consumed")

	// ErrAssertionReplayed indicates that the assertion ID was already processed (replay attack prevented).
	ErrAssertionReplayed = errors.New("saml: assertion replay attack detected")

	// ErrSignatureInvalid indicates that the cryptographic digital signature verification failed.
	ErrSignatureInvalid = errors.New("saml: digital signature verification failed")

	// ErrIssuerMismatch indicates that the assertion issuer does not match the configured IdP EntityID.
	ErrIssuerMismatch = errors.New("saml: assertion issuer mismatch")

	// ErrAudienceMismatch indicates that the AudienceRestriction did not match the SP Entity ID.
	ErrAudienceMismatch = errors.New("saml: audience restriction mismatch")

	// ErrDestinationMismatch indicates that the Destination attribute did not match the SP ACS URL.
	ErrDestinationMismatch = errors.New("saml: destination attribute mismatch")

	// ErrAssertionExpired indicates that the assertion validity window has passed (NotOnOrAfter).
	ErrAssertionExpired = errors.New("saml: assertion has expired")

	// ErrAssertionNotYetValid indicates that the assertion is not yet valid (NotBefore).
	ErrAssertionNotYetValid = errors.New("saml: assertion is not yet valid")

	// ErrStatusNotSuccess indicates that the IdP returned a non-success SAML status code.
	ErrStatusNotSuccess = errors.New("saml: idp response status code indicates failure")

	// ErrMissingSubject indicates that the SAML assertion contains no Subject NameID.
	ErrMissingSubject = errors.New("saml: assertion missing subject nameid")

	// ErrMissingEmail indicates that no valid email address could be extracted from attributes.
	ErrMissingEmail = errors.New("saml: assertion missing required email attribute")

	// ErrAccountConflict indicates that an existing Core User cannot be linked without explicit consent.
	ErrAccountConflict = errors.New("saml: an account with this email already exists")

	// ErrUnsolicitedNotAllowed indicates that an IdP-initiated login occurred but is disabled for this IdP.
	ErrUnsolicitedNotAllowed = errors.New("saml: unsolicited idp-initiated login not permitted")

	// ErrMetadataParseFailed indicates that remote or uploaded IdP metadata XML could not be parsed.
	ErrMetadataParseFailed = errors.New("saml: failed to parse idp metadata xml")
)
