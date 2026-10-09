package oauthprovider

import "errors"

// Standard OAuth 2.1 protocol errors.
var (
	// ErrInvalidRequest indicates a malformed or missing request parameter.
	ErrInvalidRequest = errors.New("oauth_provider: invalid_request")

	// ErrUnauthorizedClient indicates the client is not authorized to request an authorization code using this method.
	ErrUnauthorizedClient = errors.New("oauth_provider: unauthorized_client")

	// ErrAccessDenied indicates the resource owner or authorization server denied the request.
	ErrAccessDenied = errors.New("oauth_provider: access_denied")

	// ErrUnsupportedResponseType indicates the authorization server does not support obtaining an authorization code using this method.
	ErrUnsupportedResponseType = errors.New("oauth_provider: unsupported_response_type")

	// ErrInvalidScope indicates the requested scope is invalid, unknown, or malformed.
	ErrInvalidScope = errors.New("oauth_provider: invalid_scope")

	// ErrServerError indicates the authorization server encountered an unexpected condition.
	ErrServerError = errors.New("oauth_provider: server_error")

	// ErrTemporarilyUnavailable indicates the authorization server is temporarily overloaded or undergoing maintenance.
	ErrTemporarilyUnavailable = errors.New("oauth_provider: temporarily_unavailable")

	// ErrInvalidClient indicates client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
	ErrInvalidClient = errors.New("oauth_provider: invalid_client")

	// ErrInvalidGrant indicates the provided authorization grant or refresh token is invalid, expired, revoked, does not match the redirection URI, or was issued to another client.
	ErrInvalidGrant = errors.New("oauth_provider: invalid_grant")

	// ErrUnsupportedGrantType indicates the authorization grant type is not supported by the authorization server.
	ErrUnsupportedGrantType = errors.New("oauth_provider: unsupported_grant_type")

	// ErrPKCERequired is returned when PKCE is required (e.g. for public clients or OAuth 2.1) but missing.
	ErrPKCERequired = errors.New("oauth_provider: pkce_required")

	// ErrInvalidPKCE is returned when code_verifier fails code_challenge validation.
	ErrInvalidPKCE = errors.New("oauth_provider: invalid_pkce")

	// ErrClientRevoked is returned when the requesting client has been revoked or deactivated.
	ErrClientRevoked = errors.New("oauth_provider: client_revoked")

	// ErrRedirectURIMismatch is returned when the redirect_uri does not match exactly the registered redirect_uris.
	ErrRedirectURIMismatch = errors.New("oauth_provider: redirect_uri_mismatch")

	// ErrConsentRequired is returned when user consent has not been granted for the requested scopes.
	ErrConsentRequired = errors.New("oauth_provider: consent_required")

	// ErrNotFound is returned when a requested record is not found in the store.
	ErrNotFound = errors.New("oauth_provider: not_found")

	// ErrConflict is returned when a resource uniquely conflicts with an existing one.
	ErrConflict = errors.New("oauth_provider: conflict")
)
