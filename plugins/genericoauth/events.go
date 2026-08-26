package genericoauth

// Event topics for the Generic OAuth plugin.
const (
	// EventOAuthSignInStart is dispatched when an OAuth sign-in / authorization flow starts.
	EventOAuthSignInStart = "genericoauth:sign_in_start"

	// EventOAuthSignInSuccess is dispatched after a successful OAuth authentication and session creation.
	EventOAuthSignInSuccess = "genericoauth:sign_in_success"

	// EventOAuthSignInFailure is dispatched when an OAuth sign-in flow encounters an error.
	EventOAuthSignInFailure = "genericoauth:sign_in_failure"

	// EventOAuthAccountLinked is dispatched when a social account is bound to an existing user.
	EventOAuthAccountLinked = "genericoauth:account_linked"
)
