package oauth

import "errors"

var (
	// ErrProviderNotFound is returned when attempting to use a provider that was not registered.
	ErrProviderNotFound = errors.New("oauth: provider not found")

	// ErrProviderAlreadyExists is returned when registering a provider with a duplicate name.
	ErrProviderAlreadyExists = errors.New("oauth: provider already registered")

	// ErrInvalidState is returned when an OAuth state string is malformed or invalid.
	ErrInvalidState = errors.New("oauth: invalid state")

	// ErrStateNotFound is returned when the state session does not exist in store.
	ErrStateNotFound = errors.New("oauth: state session not found")

	// ErrStateExpired is returned when the state session has expired.
	ErrStateExpired = errors.New("oauth: state session expired")

	// ErrStateAlreadyConsumed is returned when a state session was already used (anti-replay).
	ErrStateAlreadyConsumed = errors.New("oauth: state session already consumed")

	// ErrInvalidRedirectURI is returned when the supplied redirect URI is not in the provider's allowed list or mismatches the initiated flow.
	ErrInvalidRedirectURI = errors.New("oauth: invalid redirect uri")

	// ErrPKCEMismatch is returned when PKCE verification fails.
	ErrPKCEMismatch = errors.New("oauth: pkce verification failed")

	// ErrTokenExchangeFailed is returned when exchanging the authorization code with the provider fails.
	ErrTokenExchangeFailed = errors.New("oauth: token exchange failed")

	// ErrProfileFetchFailed is returned when fetching the user profile from the provider fails.
	ErrProfileFetchFailed = errors.New("oauth: profile fetch failed")

	// ErrInvalidProfile is returned when the provider profile lacks essential identity claims (e.g. subject / ID).
	ErrInvalidProfile = errors.New("oauth: invalid provider profile")

	// ErrAccountConflict is returned when an existing user with the same email exists but account linking is disabled.
	ErrAccountConflict = errors.New("oauth: account with this email already exists")

	// ErrAccountLinkingRequiresConsent is returned when an OAuth login matches an existing user's email,
	// but automatic linking is prohibited without explicit authentication and linking consent.
	// This prevents unsafe automatic account linking attacks.
	ErrAccountLinkingRequiresConsent = errors.New("oauth: existing user found; explicit account linking required")

	// ErrUnverifiedEmailLinkingProhibited is returned when automatic account linking is requested
	// for an email that is not verified either by the provider or within core.
	ErrUnverifiedEmailLinkingProhibited = errors.New("oauth: cannot link account with unverified email")

	// ErrAccountAlreadyLinked is returned when the provider account is already linked to another user.
	ErrAccountAlreadyLinked = errors.New("oauth: provider account is already linked to a user")

	// ErrCannotUnlinkSoleAuthMethod is returned when unlinking an OAuth provider would leave the user without any credentials or accounts.
	ErrCannotUnlinkSoleAuthMethod = errors.New("oauth: cannot unlink sole authentication method")

	// ErrSignUpDisabled is returned when a new user attempts to sign up via OAuth but automatic sign up is disabled.
	ErrSignUpDisabled = errors.New("oauth: sign up is disabled for new users")

	// ErrInvalidAction is returned when a state session action does not match the attempted completion flow.
	ErrInvalidAction = errors.New("oauth: state action mismatch")

	// ErrInvalidInput is returned when required parameters are missing or invalid.
	ErrInvalidInput = errors.New("oauth: invalid input")

	// ErrAccountNotFound is returned when an account lookup yields no record.
	ErrAccountNotFound = errors.New("oauth: account not found")
)
