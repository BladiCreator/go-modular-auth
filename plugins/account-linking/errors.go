package accountlinking

import "errors"

var (
	// ErrAccountNotFound indicates that the requested account does not exist.
	ErrAccountNotFound = errors.New("account-linking: account not found")

	// ErrAccountAlreadyLinked indicates that the provider account is already linked to the current user.
	ErrAccountAlreadyLinked = errors.New("account-linking: account is already linked to this user")

	// ErrAccountConflict indicates that the provider account is already linked to another distinct user.
	// The plugin strictly forbids silent merging of two Users to prevent account takeover.
	ErrAccountConflict = errors.New("account-linking: account is already linked to another user")

	// ErrCannotUnlinkFinalAuthMethod indicates that the requested unlink operation would remove the user's
	// sole remaining authentication method, permanently orphaning the user account.
	ErrCannotUnlinkFinalAuthMethod = errors.New("account-linking: cannot unlink the user's sole remaining authentication method")

	// ErrUnauthorized indicates that the calling Principal is not authorized to link or unlink accounts for the target user.
	ErrUnauthorized = errors.New("account-linking: unauthorized actor for account operation")

	// ErrUserNotFound indicates that the target user does not exist in the Core user store.
	ErrUserNotFound = errors.New("account-linking: user not found")

	// ErrInvalidInput indicates that one or more required input arguments are missing or malformed.
	ErrInvalidInput = errors.New("account-linking: invalid input")

	// ErrTicketNotFound indicates that the linking ticket does not exist.
	ErrTicketNotFound = errors.New("account-linking: linking ticket not found")

	// ErrTicketExpired indicates that the linking ticket has exceeded its validity window.
	ErrTicketExpired = errors.New("account-linking: linking ticket has expired")

	// ErrTicketAlreadyUsed indicates that the linking ticket was already redeemed (single-use violation).
	ErrTicketAlreadyUsed = errors.New("account-linking: linking ticket was already consumed")

	// ErrProviderMismatch indicates that the linking ticket was issued for a specific provider but presented with another.
	ErrProviderMismatch = errors.New("account-linking: provider does not match linking ticket target")

	// ErrStoreRequired indicates that a persistent store is required for ticket-based linking operations.
	ErrStoreRequired = errors.New("account-linking: store is required")
)
