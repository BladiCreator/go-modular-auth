package anonymous

import "errors"

var (
	// ErrAnonymousNotFound is returned when an anonymous identity cannot be found.
	ErrAnonymousNotFound = errors.New("anonymous: identity not found")

	// ErrAnonymousExpired is returned when the anonymous identity has passed its expiration time.
	ErrAnonymousExpired = errors.New("anonymous: identity has expired")

	// ErrAlreadyConverted is returned when an operation expects an unconverted anonymous identity,
	// but the identity has already been converted to a permanent account or linked.
	ErrAlreadyConverted = errors.New("anonymous: identity has already been converted")

	// ErrUserNotAnonymous is returned when an operation requires an anonymous user,
	// but the user is already a permanent user with no active anonymous identity.
	ErrUserNotAnonymous = errors.New("anonymous: user is not an anonymous identity")

	// ErrInvalidAnonymousToken is returned when an anonymous session token is invalid, expired, or revoked.
	ErrInvalidAnonymousToken = errors.New("anonymous: invalid or expired anonymous session token")

	// ErrInvalidCredentials is returned when verification of target permanent account credentials fails during linking.
	ErrInvalidCredentials = errors.New("anonymous: invalid permanent account credentials")

	// ErrUserAlreadyExists is returned when attempting to convert to an email address that already belongs to another user.
	ErrUserAlreadyExists = errors.New("anonymous: user with this email already exists")

	// ErrInvalidEmail is returned when the email format provided during conversion is invalid.
	ErrInvalidEmail = errors.New("anonymous: invalid email address")

	// ErrInvalidPassword is returned when the password provided during conversion does not meet complexity/length policy.
	ErrInvalidPassword = errors.New("anonymous: invalid password")

	// ErrSameAccount is returned when attempting to link an anonymous user to themselves.
	ErrSameAccount = errors.New("anonymous: cannot link account to itself")

	// ErrTargetIsAnonymous is returned when attempting to link an anonymous user to another anonymous user.
	ErrTargetIsAnonymous = errors.New("anonymous: target account must be a permanent user, not an anonymous identity")

	// ErrStoreRequired is returned when initializing the plugin without a configured Store.
	ErrStoreRequired = errors.New("anonymous: store is required")

	// ErrProviderRequired is returned when converting with an external account without specifying a provider name.
	ErrProviderRequired = errors.New("anonymous: provider is required")

	// ErrProviderIDRequired is returned when converting with an external account without specifying a provider ID.
	ErrProviderIDRequired = errors.New("anonymous: provider ID is required")
)
